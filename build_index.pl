#!/usr/bin/env perl
use strict;
use warnings;
use PPI::Document;
use File::Find;
use File::Basename;
use JSON::PP;
use Cwd 'abs_path';
use POSIX qw(strftime);

# Usage: perl build_index.pl <project_root>
# Output: JSON to stdout
# Pipe to gzip for upload: perl build_index.pl /path/to/project | gzip > index.json.gz

my $root = $ARGV[0] or die "Usage: $0 <project_root>\n";
$root = abs_path($root);
die "Directory not found: $root\n" unless -d $root;

# Collect all .pm and .pl files
my @files;
find(sub {
    return if /^\./;            # skip hidden dirs/files
    return if /\bblib\b/;       # skip build artifacts
    return if /\bt\b/;          # skip test dirs
    push @files, $File::Find::name if /\.(pm|pl)$/i;
}, $root);

my %index = (
    meta => {
        project      => basename($root),
        built_at     => strftime("%Y-%m-%dT%H:%M:%SZ", gmtime),
        version      => "1",
        file_count   => 0,
        failed_count => 0,
        failed_files => [],
    },
    files   => {},  # file → {package, functions, imports, globals}
    symbols => {},  # function_name → [{file, package, line_start, line_end}]
    calls   => [],  # [{caller_file, caller_line, callee_name}]
);

my @failed;

for my $filepath (@files) {
    my $relpath = $filepath;
    $relpath =~ s{^\Q$root\E[/\\]}{};
    $relpath =~ s{\\}{/}g;

    # PPI can fail on old/unusual Perl — skip gracefully
    my $doc = eval { PPI::Document->new($filepath, readonly => 1) };
    if (!$doc || $@) {
        push @failed, $relpath;
        next;
    }

    my %file_data = (
        package   => undef,
        functions => [],
        imports   => [],
        globals   => [],
    );

    # Package name
    my $pkgs = $doc->find('PPI::Statement::Package') || [];
    $file_data{package} = $pkgs->[0]->namespace if @$pkgs;

    # Subroutine definitions with line ranges
    my $subs = $doc->find('PPI::Statement::Sub') || [];
    for my $sub (@$subs) {
        my $name = $sub->name or next;
        my $line_start = $sub->line_number + 0;
        my $line_end   = $line_start;

        if (my $block = $sub->find_first('PPI::Structure::Block')) {
            if (my $last = $block->last_token) {
                $line_end = $last->line_number + 0;
            }
        }

        push @{$file_data{functions}}, {
            name       => $name,
            line_start => $line_start,
            line_end   => $line_end,
        };

        # Global symbol index
        push @{$index{symbols}{$name}}, {
            file       => $relpath,
            package    => $file_data{package},
            line_start => $line_start,
            line_end   => $line_end,
        };
    }

    # use / require imports
    my $includes = $doc->find('PPI::Statement::Include') || [];
    for my $inc (@$includes) {
        my $type   = $inc->type   or next;
        my $module = $inc->module or next;
        next if $type eq 'no';
        push @{$file_data{imports}}, {
            module => $module,
            type   => $type,
            line   => $inc->line_number + 0,
        };
    }

    # Global variables declared with 'our'
    my $vars = $doc->find('PPI::Statement::Variable') || [];
    for my $var (@$vars) {
        next unless ($var->type // '') eq 'our';
        push @{$file_data{globals}}, map { "$_" } $var->symbols;
    }

    # Callers — find function call sites: Word followed by ( )
    # Catches: func(...), Package::func(...), $obj->method(...)
    # Does NOT catch: &func, eval "func()", dynamic dispatch — expected limitation
    my $words = $doc->find('PPI::Token::Word') || [];
    for my $word (@$words) {
        my $name = "$word";

        # Skip keywords and known non-call words
        next if $name =~ /^(if|elsif|else|unless|while|until|for|foreach|
                            sub|my|our|local|use|require|return|next|last|
                            redo|do|eval|die|warn|print|say|push|pop|shift|
                            unshift|splice|map|grep|sort|reverse|keys|values|
                            exists|delete|defined|ref|bless|package|BEGIN|END|
                            DESTROY|new|SUPER)$/x;

        # Must be followed by opening paren — signature of a function call
        my $next = $word->snext_sibling or next;
        next unless ref($next) eq 'PPI::Structure::List';

        # Strip Package:: prefix to get bare function name for lookup
        my $bare = $name;
        $bare =~ s/.*:://;
        next unless length($bare) > 1;

        push @{$index{calls}}, {
            caller_file => $relpath,
            caller_line => $word->line_number + 0,
            callee_name => $bare,
            callee_full => $name,  # keep full name for disambiguation
        };
    }

    $index{files}{$relpath} = \%file_data;
}

$index{meta}{file_count}   = scalar keys %{$index{files}};
$index{meta}{failed_count} = scalar @failed;
$index{meta}{failed_files} = \@failed;

print JSON::PP->new->utf8->canonical->encode(\%index);
