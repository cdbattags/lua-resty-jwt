use strict;
use warnings;
use Test::More;
use File::Find;

# _VERSION in lib/resty/jwt.lua is the single source of truth for the release
# version: OPM reads it from main_module, and the git tag (vX.Y.Z) must match
# it. The rockspec and dist.ini must not hard-code a version of their own.
#
# publish.yml runs this file with RELEASE_TAG set to the pushed tag, so the
# release is refused before any upload when the tag and _VERSION disagree.

sub slurp {
    my ($file) = @_;
    open my $fh, '<', $file or die "Cannot open $file: $!";
    local $/;
    return <$fh>;
}

my $jwt = slurp('lib/resty/jwt.lua');
my @versions = $jwt =~ /_VERSION\s*=\s*"([^"]*)"/g;
is(scalar @versions, 1, 'lib/resty/jwt.lua declares _VERSION exactly once');
my $version = $versions[0] // '';
like($version, qr/^\d+\.\d+\.\d+$/, "_VERSION \"$version\" is MAJOR.MINOR.PATCH");

# no other module carries a version of its own that could go stale
my @modules;
find(sub { push @modules, $File::Find::name if /\.lua$/ }, 'lib');
for my $module (sort grep { $_ ne 'lib/resty/jwt.lua' } @modules) {
    unlike(slurp($module), qr/_VERSION\s*=/, "$module declares no _VERSION");
}

my $rockspec = slurp('lua-resty-jwt-dev-0.rockspec');
like($rockspec, qr/^version\s*=\s*'dev-0'\s*$/m,
    'rockspec keeps version dev-0 (luarocks new_version sets the release version)');
unlike($rockspec, qr/^\s*(tag|branch)\s*=/m,
    'rockspec source does not pin a tag or branch');

my $dist = slurp('dist.ini');
unlike($dist, qr/^\s*version\s*=/m,
    'dist.ini does not set a version (OPM reads _VERSION from main_module)');
like($dist, qr{^main_module\s*=\s*lib/resty/jwt\.lua\s*$}m,
    'dist.ini main_module is lib/resty/jwt.lua');

SKIP: {
    my $tag = $ENV{RELEASE_TAG};
    skip 'RELEASE_TAG is not set', 1 unless defined $tag && length $tag;
    is($tag, "v$version", "release tag matches v\$_VERSION");
}

done_testing();
