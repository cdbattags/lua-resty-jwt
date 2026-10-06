use strict;
use warnings;
use Test::More;

# Every GitHub workflow runs with a read-only token by default, and no
# checkout leaves that token in .git/config for later steps to read.
my @workflows = glob('.github/workflows/*.yml');
ok(scalar @workflows > 0, 'found workflow files');

for my $file (@workflows) {
    open my $fh, '<', $file or die "Cannot open $file: $!";
    my $yml = do { local $/; <$fh> };
    close $fh;

    like($yml, qr/^permissions:\n  contents: read\n/m, "$file defaults to a read-only token");

    my $checkouts = () = $yml =~ /uses: actions\/checkout@/g;
    my $no_persist = () = $yml =~ /^\s+persist-credentials: false$/mg;
    ok($checkouts > 0, "$file checks out the repository");
    is($no_persist, $checkouts, "$file: every checkout sets persist-credentials: false");
}

done_testing();
