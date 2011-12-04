package Net::OpenSSH::Gateway::Backend;

use strict;
use warnings;
use Carp;
use Fcntl;

require Net::OpenSSH;

sub _array_or_scalar_to_list { map { defined($_) ? (ref $_ eq 'ARRAY' ? @$_ : $_ ) : () } @_ }

sub _default_command_names { {} }

sub _default_private_opts { {} }

sub _backend_name {
    my $class = ref shift;
    $class =~ s/.*:://;
    $class;
}

sub _command { shift->_backend_name }

sub _search_command {
    my ($self, $name) = @_;
    $name = $self->_command unless defined $name;
    my $names = $self->{cmds}{$name};
    my @names = ($names ? @$names : $name);
    # TODO: handle the case where an absolute path is passed
    if (defined $self->{path}) {
        for my $name (@names) {
            # TODO: set and check cmd_cache here
            my $via_ssh = $self->{via_ssh};
            for my $path (@{$self->{path}}) {
                my $full = "$path$name";
                if ($via_ssh ? $via_ssh->test(test => -x => $full) : -x $full) {
                    if (not $self->{check} or $self->_check_command_version($full)) {
                        return $full;
                    }
                }
            }
        }
        $self->_push_error("unable to find any of @names programs");
    }
    else {
        my $full = $names[0];
        if (defined $full) {
            if (not $self->{check} or $self->_check_command_version($full)) {
                return $self->_slave_quote($names[0]);
            }
        }
        else {
            $self->_push_error("no command found for $name");
        }
    }
    return
}

sub _check_command_version {
    my ($self, $full) = @_;
    my @v = $self->_command_version_args or return 1;
    my $cmd = $self->_quote_command($full, @v);
    my $out = $self->_qx("$cmd 2>&1");
    if ($self->_check_command_version_output($out)) {
        return 1;
    }
    $self->_push_error("discarding command $cmd because it failed the version test");
    undef;
}

sub _check_command_version_output { 1 }

sub _version_to_number {
    my ($self, $ver) = @_;
    my $n = 0;
    my $f = 1;
    for (split /\D+/, $ver) {
        $n += ($_||0) * $f;
        $f *= 0.01;
    }
    $n;
}

sub _command_version_args { }

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
    $scheme =~ s/^socks(s?)$/socks4$1/;
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
    $url = join( '',
                 $scheme, "://",
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

sub _parse_connection_opts {
    my $self = shift;
    my %opts = (@_ & 1 ? (host => @_) : @_);
    my $no_host;
    if (ref $self) {
        for (qw(host port)) {
            $opts{$_} = $self->{$_} unless defined $opts{$_}
        }
    }

    if (not defined $opts{host}) {
        $opts{host} = 'UNKNOWN';
        $no_host = 1;
    }

    if (my $conn = Net::OpenSSH->parse_connection_opts(\%opts)) {
        $opts{$_} = $conn->{$_} for keys %$conn;
    }

    if ($no_host) {
        delete $opts{host};
    }
    else {
        $opts{port} ||= 22;
    }

    %opts;
}

sub new {
    my $class = shift;
    my %opts = $class->_parse_connection_opts(@_);

    my @proxies = map $class->_parse_proxy_opts($_),
        _array_or_scalar_to_list(delete $opts{proxies} || delete $opts{proxies});

    my $check = delete $opts{check};
    $check = 1 unless defined $check;

    my $name = $class;
    $name =~ s/.*:://;

    my $self = { my_name     => $name,
                 host        => $opts{host},
                 port        => $opts{port},
                 ipv6        => $opts{ipv6},
                 via_ssh     => $opts{via_ssh},
                 timeout     => $opts{timeout} || 120,
                 slave_quote => 1,
                 check       => $check,
                 errors      => [],
                 proxies     => \@proxies };
    bless $self, $class;

    if (defined $opts{path}) {
        my @path = _array_or_scalar_to_list($opts{path});
        s|/*$|/| for @path;
        $self->{path} = \@path;
    }

    my $backend_name = quotemeta $self->_backend_name;
    my %private = %{$self->_default_private_opts};
    my %cmds = %{$self->_default_command_names};

    for (keys %opts) {
        $private{$1} = $opts{$_} if /^${backend_name}_(.*)/;
        $cmds{$1} = [_array_or_scalar_to_list $opts{$_}] if /^(.*)_cmd/;
    }
    $self->{private} = \%private;
    $self->{cmds} = \%cmds;
    $self;
}

sub proxy_command {
    my $self = shift;
    $self->check_args or return;
    my %opts = $self->_parse_connection_opts(@_);
    my ($cmd_path) = $self->_search_command or return;
    my @args = $self->_command_args(%opts) or return;
    return $self->_quote_command($cmd_path, @args);
}

sub _qx {
    my ($self, $cmd, $oneline, $max) = @_;
    $max ||= 8000;
    if (open my $s, "$cmd |") {
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
            last if ( time > $time_limit or
                      length $buffer > $max or
                      ( $oneline and $buffer =~ /\n/) );
        }
        time > $time_limit and $self->_push_error(warning => "remote command '$cmd' timed out");
        close $s;
        return $buffer;
    }
    else {
        $self->_push_error("unable to run command '$cmd': $!");
        return '';
    }
}

sub check_args { 1 }

sub check {
    my $self = shift;
    my %opts = $self->_parse_connection_opts(@_);
    unless (defined $opts{host}) {
        $self->_push_error(warning => 'gateway not checked because host has not been defined yet');
        return 1;
    }

    local $self->{slave_quote};

    my $cmd = $self->proxy_command(%opts);
    defined $cmd or return;

    my $out = $self->_qx("$cmd </dev/null 2>&1", 1);
    return 1 if $out =~ /^SSH.*\x0d\x0a/;

    $self->_push_error("gateway $self->{my_name} check failed");
    return
}

sub _push_error {
    my $self = shift;
    push @{$self->{errors}}, join(': ', @_);
}

sub errors { @{shift->{errors}} }

sub before_ssh_connect {
    my $self = shift;
    my $ssh = $self->{ssh_via};
    if ($ssh and !$ssh->wait_for_master(@_)) {
        $self->_push_error("SSH gateway failed", $ssh->error) if $ssh->error;
        return;
    }
    1
}

my %opt_pattern = ( host => '%h',
                    port => '%p',
                    user => '%u' );

sub _slave_quote_opt {
    my ($self, $key, %opts) = @_;
    my $opt = $opts{$key};
    return $opt unless $self->{slave_quote};

    if (defined $opt) {
        $opt =~ s/%/%%/g;
        return $opt;
    }
    $opt_pattern{$key};
}

sub _slave_quote {
    my ($self, @args) = @_;
    if ($self->{slave_quote}) {
        defined and s/%/%%/g for @args;
    }
    wantarray ? @args : $args[0]
}

sub after_ssh_connect { }

sub after_ssh_disconnect { }

1;
