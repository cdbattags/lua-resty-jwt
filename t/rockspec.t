use strict;
use warnings;
use Test::More;
use File::Find;

my $rockspec_file = 'lua-resty-jwt-dev-0.rockspec';

# Parse file paths declared in rockspec modules
open my $fh, '<', $rockspec_file or die "Cannot open $rockspec_file: $!";
my $rockspec = do { local $/; <$fh> };
close $fh;

my %declared_files;
while ($rockspec =~ /=\s*'([^']+\.lua)'/g) {
    $declared_files{$1} = 1;
}

# Find all .lua files under lib/
my @lib_files;
find(sub {
    return unless /\.lua$/;
    push @lib_files, $File::Find::name;
}, 'lib');

ok(scalar @lib_files > 0, 'found lua files under lib/');

for my $file (sort @lib_files) {
    ok(exists $declared_files{$file}, "$file is declared in $rockspec_file");
}

# Verify declared files actually exist on disk
for my $file (sort keys %declared_files) {
    ok(-f $file, "rockspec module $file exists on disk");
}

done_testing();
