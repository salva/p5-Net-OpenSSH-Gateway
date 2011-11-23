package Net::OpenSSH::Gateway::Backend;

use strict;
use warnings;
use Carp;
use Fcntl;

require Net::OpenSSH;

sub _array_or_scalar_to_list { map { defined($_) ? (ref $_ eq 'ARRAY' ? @$_ : $_ ) : () } @_ }

sub _search_executable {
    my ($self, @names) = @_;
    if (defined $self->{path}) {
        for my $name (@names) {
            my $via_ssh = $self->{via_ssh};
            for my $path (@{$self->{path}}) {
                my $full = "$path$name";
                if ($via_ssh) {
                    return $full if $via_ssh->test(test => -x => $full);
                }
                else {
                    return $full if -x $full;
                }
            }
        }
        $self->_set_error("unable to find any of @names programs");
        return;
    }
    else {
        return $names[0]
    }
}

sub _quote_command {
    my ($self, @cmd) = @_;
    my $ssh = $self->{via_ssh};
    return scalar( $ssh
                   ? $ssh->make_remote_command(@cmd)
                   : Net::OpenSSH->shell_quote(@cmd) );
}

my %default_proxy_port = ( http    => 8080,
                           https   => 8443,
                           socks4  => 1080,
                           socks5  => 1080,
                           socks4s => 1443,
                           socks5s => 1443 );

sub _parse_proxy_opts {
    my ($class, $proxy) = @_;
    $proxy = { url => $proxy } unless ref $proxy;

    my $url = $proxy->{url};
    my ($scheme, $user, $password, $host, $port, $ssl);

    if (defined $url) {
        ($scheme, $user, $password, $host, $port) =
            $url =~ m{^(?:(https?|socks[45]?s?)://)?(?:([^:]+?)(?::(.*))?\@)?([a-z0-9][\w-]*(?:\.[a-z0-9][\w-]*)*)(?::([\w+]+))?/?$}i
                or croak "bad proxy url '$url'";
    }

    $scheme = $proxy->{scheme} unless defined $scheme;
    $scheme = 'http' unless defined $scheme;
    $scheme =~ s/^socks(s?)$/socks5$1/;
    defined $default_proxy_port{$scheme} or croak "bad proxy scheme '$scheme'";

    $ssl = 1 if $scheme =~ /s$/;
    $ssl = $proxy->{ssl} unless defined $ssl;

    $scheme =~ s/s*$/s/ if $ssl;

    $host = $proxy->{host} unless defined $host;
    defined $host or croak "proxy name or address missing";

    $port = $proxy->{port} unless defined $port;
    $port = $default_proxy_port{$scheme} unless defined $port;
    if ($port =~ /\D/) {
        $port = getservbyname($port, 'tcp')
            or croak "invalid proxy port specification '$port'";
    }

    $user   = $proxy->{user} unless defined $user;
    $password = $proxy->{password} unless defined $password;

    # sanitize url:
    $url = join( $scheme, "://",
                 (defined $user ? ($user, '', (defined $password ? (':', $password) : ()), '@' ) : ()),
                 $host,
                 (defined $port ? (':', $port) : ()) );

    return { url      => $url,
             scheme   => $scheme,
             host     => $host,
             port     => $port,
             user     => $user,
             password => $password,
             ssl      => $ssl };
}

sub new {
    my ($class, %opts) = @_;

    my $conn = Net::OpenSSH->parse_connection_opts(\%opts) || {};
    %opts = (%$conn, %opts);

    my @proxies = map $class->_parse_proxy_opts($_),
        _array_or_scalar_to_list(delete $opts{proxies} || delete $opts{proxies});

    my $check = delete $opts{check};
    $check = 1 unless defined $check;

    my $self = { host    => delete $opts{host},
                 port    => delete $opts{port} || 22,
                 ipv6    => delete $opts{ipv6},
                 via_ssh => delete $opts{via_ssh},
                 timeout => delete $opts{timeout} || 120,
                 check   => $check,
                 error   => undef,
                 proxies => \@proxies };

    if (defined $opts{path}) {
        my @path = _array_or_scalar_to_list(delete $opts{path});
        s|/*$|/| for @path;
        $self->{path} = \@path;
    }
    bless $self, $class;
}

sub proxy_command {
    my $self = shift;
    my @cmd_names = $self->_command_names;
    my ($cmd_name) = $self->_search_executable(@cmd_names) or return;
    my @args = $self->_command_args or return;
    return $self->_quote_command($cmd_name, @args);
}

sub check {
    my $self = shift;

    my ($cmd) = $self->proxy_command or return;
    return 1 unless $self->{check};

    if (open my $s, "$cmd </dev/null |") {
        fcntl($s, F_SETFL, fcntl($s, F_GETFL, 0) | O_NONBLOCK);
        binmode $s;
        my $buffer = '';
        my $time_limit = time + $self->{timeout};
        while (1) {
            my $iv = '';
            vec($iv, fileno($s), 1) = 1;
            if (select($iv, undef, undef, 1) > 0) {
                sysread($s, $buffer, 1000, length $buffer) or last;
                $buffer =~ /\x0d\x0a/ and last;
            }
            last if time > $time_limit or length $buffer > 2000;
        }
        close $s;
        return scalar($buffer =~ /^SSH.*\x0d\x0a/)
    }
    else {
        $self->_set_error("unable to run command '$cmd': $!");
        return
    }
}

sub _set_error {
    my $self = shift;
    $self->{error} = join(': ', @_);
}

sub error { shift->{error} }

sub before_ssh_connect {
    my $self = shift;
    my $ssh = $self->{ssh_via};
    if ($ssh and !$ssh->wait_for_master(@_)) {
        $self->_set_error("SSH gateway failed", $ssh->error) if $ssh->error;
        return;
    }
    1
}

sub after_ssh_connect { }

sub after_ssh_disconnect { }

1;
