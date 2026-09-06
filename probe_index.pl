#!/usr/bin/perl
# Разведка формата индекса. Запускается там, где лежат чанки: нужен только
# Perl с JSON::PP (ядро с 5.14). Python не требуется.
#
# По умолчанию значения обезличены — пути, имена функций, пакетов и модулей
# заменяются плейсхолдерами.
# Имена ключей, типы, счётчики, номера строк и даты остаются как есть.
#
#   perl probe_index.pl index.part-001.json.gz
#   perl probe_index.pl chunks/*.json.gz > структура.txt
#   perl probe_index.pl --raw index.json      # без обезличивания, только внутри
#
# Скрипт только читает. Ничего не пишет и никуда не ходит по сети.

use strict;
use warnings;
use JSON::PP;

my $SAFE = 1;
my @files;
for my $arg (@ARGV) {
    if ($arg eq '--raw')  { $SAFE = 0; next }
    if ($arg eq '--safe') { $SAFE = 1; next }
    push @files, $arg;
}

unless (@files) {
    print "Использование: perl probe_index.pl <файл индекса> [ещё файлы]\n";
    print "               perl probe_index.pl --raw <файл>   (без обезличивания)\n";
    exit 1;
}

my %slot;
my %counter;

# Ключи, значения которых считаем производными от кода
my %SENSITIVE = map { $_ => 1 } qw(
    file path filepath relpath caller_file
    name subname function method
    package callee_name callee_full
    module varname var project root repo failed_files
);

my %KIND = (
    file        => 'ФАЙЛ',   path      => 'ФАЙЛ',   filepath => 'ФАЙЛ',
    relpath     => 'ФАЙЛ',   caller_file => 'ФАЙЛ', failed_files => 'ФАЙЛ',
    package     => 'ПАКЕТ',  module    => 'МОДУЛЬ',
    varname     => 'ПЕРЕМЕННАЯ', var   => 'ПЕРЕМЕННАЯ',
    project     => 'ПРОЕКТ', root      => 'ПУТЬ',   repo => 'ПРОЕКТ',
);

sub mask {
    my ($value, $key) = @_;
    return $value unless $SAFE;
    return $value unless defined $value;
    return $value if ref $value;
    return $value unless defined $key && $SENSITIVE{$key};
    my $kind = $KIND{$key} // 'ИМЯ';
    my $id = "$kind\0$value";
    unless (exists $slot{$id}) {
        $slot{$id} = sprintf('<%s_%d>', $kind, ++$counter{$kind});
    }
    return $slot{$id};
}

# Рекурсивно обезличивает структуру, сохраняя форму
sub mask_deep {
    my ($node, $key) = @_;
    if (ref $node eq 'HASH') {
        return { map { $_ => mask_deep($node->{$_}, $_) } keys %$node };
    }
    if (ref $node eq 'ARRAY') {
        return [ map { mask_deep($_, $key) } @$node ];
    }
    return mask($node, $key);
}

my $J = JSON::PP->new->canonical->allow_nonref;

sub show {
    my ($node, $key, $limit) = @_;
    $limit //= 220;
    my $text = $J->encode(mask_deep($node, $key));
    $text = substr($text, 0, $limit) . '…' if length($text) > $limit;
    return $text;
}

sub type_of {
    my $node = shift;
    return 'массив'  if ref $node eq 'ARRAY';
    return 'объект'  if ref $node eq 'HASH';
    return 'булево'  if ref $node eq 'JSON::PP::Boolean';
    return 'null'    unless defined $node;
    return $node =~ /^-?\d+(?:\.\d+)?$/ ? 'число' : 'строка';
}

sub size_of {
    my $node = shift;
    return scalar @$node        if ref $node eq 'ARRAY';
    return scalar keys %$node   if ref $node eq 'HASH';
    return undef;
}

sub slurp {
    my $path = shift;
    open my $fh, '<:raw', $path or die "не открывается $path: $!\n";
    my $head;
    read $fh, $head, 2;
    close $fh;

    if (defined $head && $head eq "\x1f\x8b") {
        my $data;
        if (eval { require IO::Uncompress::Gunzip; 1 }) {
            IO::Uncompress::Gunzip::gunzip($path => \$data)
                or die "не распаковывается $path: $IO::Uncompress::Gunzip::GunzipError\n";
            return $data;
        }
        # запасной путь, если модуля нет
        $data = qx{gzip -dc "$path"};
        die "не распаковывается $path (нет IO::Uncompress::Gunzip и gzip)\n" unless length $data;
        return $data;
    }

    open my $in, '<:raw', $path or die "не открывается $path: $!\n";
    local $/;
    my $data = <$in>;
    close $in;
    return $data;
}

# --- разбор одного файла ---

sub probe {
    my $path = shift;
    my $bytes = -s $path;
    printf "\n=== %s  (%s байт на диске)\n", $path, commify($bytes);

    my $data = eval { slurp($path) };
    if ($@) { print "    $@"; return }
    printf "    после распаковки: %s байт\n", commify(length $data);

    my $obj = eval { $J->decode($data) };
    if ($@) {
        my $err = $@; $err =~ s/\s+$//;
        print "    ЦЕЛЬНЫМ JSON НЕ РАЗБИРАЕТСЯ\n";
        print "    ошибка парсера: $err\n";
        probe_lines($data);
        return;
    }

    if (ref $obj eq 'ARRAY') {
        printf "    ФОРМА: JSON-массив, %d элементов\n", scalar @$obj;
        print  "    первый элемент:\n";
        report_object($obj->[0], '        ') if @$obj;
        return;
    }
    if (ref $obj ne 'HASH') {
        print "    ФОРМА: не объект и не массив — ", type_of($obj), "\n";
        return;
    }

    print "    ФОРМА: один JSON-объект\n";
    report_object($obj, '    ');
}

sub probe_lines {
    my $data = shift;
    my @lines = grep { /\S/ } split /\n/, $data;
    printf "    пробую построчно (JSON Lines): %d непустых строк\n", scalar @lines;

    my ($ok, $bad, $first) = (0, 0, undef);
    my $limit = @lines > 200 ? 200 : scalar @lines;
    for my $i (0 .. $limit - 1) {
        my $o = eval { $J->decode($lines[$i]) };
        if ($@) { $bad++; next }
        $ok++;
        $first //= $o;
    }
    printf "    разобралось строк (из первых %d): %d, не разобралось: %d\n", $limit, $ok, $bad;

    if (!$ok) {
        print "    ФОРМА: неизвестна — ни цельный JSON, ни JSON Lines.\n";
        print "    Вероятно файл обрезан или это несколько объектов подряд без разделителя.\n";
        printf "    длина первой строки: %d символов\n", length($lines[0] // '');
        print  "    (сырой фрагмент не печатается: режим обезличивания)\n" if $SAFE;
        print  "    начало файла: ", substr($data, 0, 300), "\n" unless $SAFE;
        return;
    }

    print "    ФОРМА: JSON Lines, по объекту на строку\n";
    print "    первая разобранная строка:\n";
    report_object($first, '        ');
}

sub report_object {
    my ($obj, $ind) = @_;
    unless (ref $obj eq 'HASH') {
        print "$ind", type_of($obj), "\n";
        return;
    }

    my @keys = sort keys %$obj;
    print "$ind","КЛЮЧИ ВЕРХНЕГО УРОВНЯ: ", join(', ', @keys), "\n";
    for my $k (@keys) {
        my $v = $obj->{$k};
        my $size = size_of($v);
        printf "$ind  %-14s %s%s\n", $k, type_of($v),
               defined $size ? ", элементов: $size" : '';
    }

    # files
    my $files = $obj->{files};
    if (ref $files eq 'HASH') {
        my ($k) = sort keys %$files;
        print "$ind","FILES: словарь путь -> данные\n";
        if (defined $k) {
            print "$ind  пример ключа: ", $J->encode(mask($k, 'file')), "\n";
            print "$ind  запись про файл: ", show($files->{$k}, 'file', 700), "\n";
            if (ref $files->{$k} eq 'HASH') {
                print "$ind  поля записи: ", join(', ', sort keys %{$files->{$k}}), "\n";
            }
        }
    } elsif (ref $files eq 'ARRAY') {
        print "$ind","FILES: МАССИВ, а не словарь — базовый загрузчик такого не ждёт\n";
        print "$ind  первый элемент: ", show($files->[0], 'file', 700), "\n" if @$files;
    } else {
        print "$ind","FILES: ключа нет\n";
    }

    # calls
    my $calls = $obj->{calls};
    if (ref $calls eq 'ARRAY') {
        printf "$ind%s: массив, %d элементов\n", 'CALLS', scalar @$calls;
        print "$ind  пример: ", show($calls->[0], 'callee_name', 400), "\n" if @$calls;
        print "$ind  поля: ", join(', ', sort keys %{$calls->[0]}), "\n"
            if @$calls && ref $calls->[0] eq 'HASH';
    } else {
        print "$ind","CALLS: раздела нет\n";
    }

    # meta и признаки чанка
    my $meta = $obj->{meta};
    if (ref $meta eq 'HASH') {
        print "$ind","META: ", show($meta, undef, 600), "\n";
    } else {
        print "$ind","META: раздела нет\n";
    }

    my @chunk_keys = grep { /chunk|part|batch|offset|total|seq|page|index_of/i }
                     (keys %$obj, ref $meta eq 'HASH' ? keys %$meta : ());
    print "$ind","ПРИЗНАКИ ЧАНКА: ",
          (@chunk_keys ? join(', ', sort @chunk_keys) : 'не найдено'), "\n";

    # сверка с базовым форматом
    my @have = ();
    my @miss = ();
    for my $k (qw(meta files calls)) {
        exists $obj->{$k} ? push(@have, $k) : push(@miss, $k);
    }
    my %known = map { $_ => 1 } qw(meta files calls symbols);
    my @extra = grep { !$known{$_} } @keys;
    print "$ind","СВЕРКА С БАЗОВЫМ ФОРМАТОМ:\n";
    print "$ind  есть: ", (@have ? join(', ', @have) : '—'), "\n";
    print "$ind  нет:  ", (@miss ? join(', ', @miss) : '—'), "\n";
    print "$ind  новые ключи: ", (@extra ? join(', ', @extra) : '—'), "\n";

    if (ref $files eq 'HASH') {
        my ($k) = sort keys %$files;
        if (defined $k && ref $files->{$k} eq 'HASH') {
            my @fmiss = grep { !exists $files->{$k}{$_} }
                        qw(package functions imports globals);
            print "$ind  в записи файла не хватает: ",
                  (@fmiss ? join(', ', @fmiss) : '— всё на месте'), "\n";
            my $fns = $files->{$k}{functions};
            if (ref $fns eq 'ARRAY' && @$fns && ref $fns->[0] eq 'HASH') {
                print "$ind  поля функции: ", join(', ', sort keys %{$fns->[0]}), "\n";
            }
        }
    }
    if (ref $calls eq 'ARRAY' && @$calls && ref $calls->[0] eq 'HASH') {
        my @cmiss = grep { !exists $calls->[0]{$_} }
                    qw(caller_file caller_line callee_name callee_full);
        print "$ind  в записи вызова не хватает: ",
              (@cmiss ? join(', ', @cmiss) : '— всё на месте'), "\n";
    }
}

sub commify {
    my $n = reverse shift // 0;
    $n =~ s/(\d{3})(?=\d)/$1 /g;
    return scalar reverse $n;
}

print "РЕЖИМ: значения обезличены\n" if $SAFE;
print "РЕЖИМ RAW: реальные имена и пути ПЕЧАТАЮТСЯ\n" unless $SAFE;

for my $f (@files) {
    unless (-e $f) { print "\nнет файла: $f\n"; next }
    probe($f);
}
print "\n";
