package Net::OpenSSH::Gateway;

our $VERSION = '0.01';

use 5.010;
use strict;
use warnings;
use Carp;
use Fcntl qw(F_GETFL F_SETFL O_NONBLOCK);
use Net::OpenSSH;

my @default_backends = qw(ssh_w netcat socat socat2 ncat perl pnc);

sub _array_or_scalar_to_list { map { defined($_) ? (ref $_ eq 'ARRAY' ? @$_ : $_ ) : () } @_ }

sub _first_defined { defined and return $_ for @_; () }

my %default_proxy_port = ( http    => 8080,
                           https   => 8443,
                           socks4  => 1080,
                           socks5  => 1080,
                           socks4s => 1443,
                           socks5s => 1443,
                           ssh     => 22,
                           ssl     => 22 );

sub _parse_proxy_opts {
    my ($class, $proxy) = @_;
    $proxy = { url => $proxy } unless ref $proxy;

    my $url = $proxy->{url};
    my ($scheme, $user, $password, $host, $port, $ssl);

    if (defined $url) {
        ($scheme, $user, $password, $host, $port) =
            $url =~ m{^(?:(ssl|ssh|https?|socks[45]?s?)://)?(?:([^:]+?)(?::(.*))?\@)?([a-z0-9][\w-]*(?:\.[a-z0-9][\w-]*)*)(?::([\w+]+))?/?$}i
                or croak "bad proxy url '$url'";
    }

    $scheme = $proxy->{scheme} unless defined $scheme;
    $scheme = 'http' unless defined $scheme;
    $scheme =~ s/^socks(s?)$/socks4$1/;
    defined $default_proxy_port{$scheme} or croak "bad proxy scheme '$scheme'";

    $host = $proxy->{host} unless defined $host;

    $port = $proxy->{port} unless defined $port;
    $port = $default_proxy_port{$scheme} unless defined $port;
    if ($port =~ /\D/) {
        $port = getservbyname($port, 'tcp')
            or croak "invalid proxy port specification '$port'";
    }

    $user   = $proxy->{user} unless defined $user;
    $password = $proxy->{password} unless defined $password;

    if ($scheme eq 'ssl') {
        $host = 'localhost' unless defined $host;
        $ssl = 1;
    }
    else {
        defined $host or croak "proxy name or address missing";

        $ssl = 1 if $scheme =~ /s$/;
        $ssl = $proxy->{ssl} unless defined $ssl;

        if ($ssl) {
            $scheme eq 'ssh' and croak "SSL is not supported for SSH gateways";
            $scheme =~ s/s*$/s/;
        }
    }

    my %proxy = ( %$proxy,
                  scheme   => $scheme,
                  host     => $host,
                  port     => $port,
                  user     => $user,
                  password => $password,
                  ssl      => $ssl );

    # sanitize url:
    $proxy{url} = $class->_make_proxy_url(\%proxy);
    \%proxy
}

sub _make_proxy_url {
    my ($self, $proxy) = @_;

    my $auth = $proxy->{user};
    if (defined $auth) {
        $auth = "$auth:$proxy->{password}" if defined $proxy->{password};
        $auth .= '@';
    }
    else {
        $auth = '';
    }

    my $port = $proxy->{port};
    $port = (defined $port ? ":$port" : '');

    my $url = join( '', $proxy->{scheme}, "://",
                    $auth, $proxy->{host}, $port );

}

sub _collapse_ssl_proxies {
    my $self = shift;
    my @ok;
    while (my $proxy = shift) {
        if (@_ and $proxy->{schema} eq 'ssl') {
            my $next = $_[0];
            if ($next->{schema} =~ /^(?:http|socks[45])$/ ) {
                $next->{schema} .= 's';
                $next->{ssl} = 1;
                $next->{url} = $self->_make_proxy_url($proxy);
                next;
            }
        }
        push @ok, $proxy;
    }
    @ok
}

my @net_openssh_ctor_opts = qw(host port user password passphrase key_path batch_mode
                               ctl_dir ssh_cmd scp_cmd rsync_cmd timeout strict_mode
                               master_opts default_stdin_fh default_stdout_fh default_stderr_fh
                               default_stdin_file default_stdout_file default_stderr_file
                               master_stdout_fh master_stderr_fh master_stdout_discard
                               master_stderr_discard);

sub find_gateway {
    my $class = shift;
    my %opts = (@_ & 1 ? (host => @_) : @_);
    my $errors;
    if (exists $opts{errors}) {
        for (my $i = (@_ & 1); $i < @_; $i += 2) {
            if ($_[$i] eq 'errors') {
                local ($SIG{__DIE__}, $@);
                eval { $errors = ($_[$i+1] ||= []) };
                last;
            }
        }
        ref $errors eq 'ARRAY'
            or croak "errors argument must be an array reference or an unitialized variable";
    }
    else {
        $errors = [];
    }
    @$errors = ();

    $opts{check} = 1 unless defined $opts{check};

    my @proxies = $class->_collapse_ssl_proxies(map $class->_parse_proxy_opts($_),
                                                _array_or_scalar_to_list
                                                _first_defined @opts{qw(proxies proxy)});

    my $via_ssh = $opts{via_ssh};

    while (1) {
        my $backends = _first_defined @opts{qw(backends backend)}, \@default_backends;
        my $check;

        my $ssh_proxy;
        my @before_proxies;
        my %ssh_opts;
        my ($top_proxy) = grep $proxies[$_]{scheme} eq 'ssh', 0..$#proxies;
        if (defined $top_proxy) {
            $ssh_proxy = $proxies[$top_proxy];
            $backends = _first_defined @{$ssh_proxy}{qw(backends backend)}, $backends;
            for (@net_openssh_ctor_opts) {
                my $v = $ssh_proxy->{$_};
                $ssh_opts{$_} = $v if defined $v;
            }
            $ssh_opts{batch_mode} = 1 unless defined $ssh_opts{batch_mode};
            $check = $ssh_proxy->{check};
            @before_proxies = splice @proxies, 0, $top_proxy;
            shift @proxies;
        }
        else {
            @before_proxies = @proxies;
        }

        $check = $opts{check} unless defined $check;

        if (@before_proxies or $via_ssh) {

            for my $backend (_array_or_scalar_to_list $backends) {
                $backend =~ /\W/ and croak "bad backend name $_";

                my $class = __PACKAGE__ . '::Backend::' . $backend;
                unless(eval "require $class; 1") {
                    push @$errors, "unable to load backend $class: $@";
                    next;
                };
                my $gateway = $class->new(%opts, %ssh_opts, proxies => \@before_proxies, via_ssh => $via_ssh);
                if ($gateway->check_args and
                    (!$check or $gateway->check)) {
                    if ($ssh_proxy) {
                        my $ssh = Net::OpenSSH->new(%ssh_opts, gateway => $gateway);
                        if ($ssh->error) {
                            push @$errors, "open connection to SSH gateway failed: ". $ssh->error;
                            return;
                        }
                        $via_ssh = $ssh;
                        next;
                    }
                    else {
                        return $gateway
                    }
                }
                push @$errors, $gateway->errors;
            }
            push @$errors, "no suitable backend found";
            return;
        }
        elsif ($ssh_proxy) {
            my $ssh = Net::OpenSSH->new(%ssh_opts);
            if ($ssh->error) {
                push @$errors, "open connection to SSH gateway failed: ". $ssh->error;
                return;
            }
            $via_ssh = $ssh;
            next;
        }
        else {
            push @$errors, "no gateway required to establish SSH connection";
            return;
        }
    }
}

1;
__END__

=head1 NAME

Net::OpenSSH::Gateway - Let Net::OpenSSH connect through proxies and gateways

=head1 SYNOPSIS

  use Net::OpenSSH;

  my $ssh = Net::OpenSSH->new($target,
                              gateway => { proxies => ['https://one.proxy.org',
                                                       'socks://proxy.com',
                                                       'ssh://some.ssh.server',
                                                       'http://two.athome.org'],
                                           backends => [qw(socat2 perl)] });

  $ssh->system('ls');

=head1 DESCRIPTION

This module tries to find a way to connect to some remote SSH server
crossing through proxies and SSH gateways chains.

Under the hood it tries to produce a shell command that can be passed
to OpenSSH client using the C<ProxyCommand> directive (see
L<ssh_config(5)>).

The module would try to use different commands in order to establish
the connection as for instance L<netcat(1)>, L<socat(1)>, L<ncat(1)>,
L<proxytunnel> or even Perl one-liners.

In order to cross through SSH gateways, intermediate Net::OpenSSH
objects are also created.

As the list of commands supported have different capabilities (for
instance, they may only support crossing a fixed number of proxies or
lack support for the some proxying protocol or SSL), a set of backend
modules is used to implement support for every one of them.

When one new gateway object is requested, the backend modules are
tried in order until one of then is able to fulfill the given
requirements.

=head2 API

This module has and object oriented interface exposing the following
methods:

=over 4

=item Net::OpenSSH::Gateway->find_gateway($target, %opts)

=item Net::OpenSSH::Gateway->find_gateway(%opts)

Tries to find a way to reach the target host through the given list of
proxies and gateways.

Returns a gateway object that can be passed to Net::OpenSSH.

The accepted options are:

=over 4

=item backends => \@backends

A list of the backend modules that should be tried when looking for a
way to connect to the remote host. If not given, a sane default list
is used.

=item proxies => $url

=item proxies => \@url

=item proxies => \@proxy_description

A list of proxies that should be crossed in order to reach the target
host.

A proxy declaration can be a single declaration as for instance:

  http://host:port
  https://user:password@host:port
  socks4://host
  ssh://user@host
  ssl://

or a hash containing some of the following entries:

=over 4

=item url

=item scheme

=item host

=item port

=item user

=item password

=item ssl

=back

or others specific to the proxing protocol or private to some backend.

=back

=item via_ssh => $ssh

A Net::OpenSSH object with an open connection to a SSH gateway that
should be used as an starting point on the connection chain.

=item check => $bool

When the backends should check that the generated command works
running it and checking if an SSH server lays at the other side.

The default value is true when the C<$target> object is given
(otherwise, it is not possible to check it). Besides running the
generated ProxyCommand command. Other actions are performed in order
to check the validity of the command as for instance that the base
command exists on the machine or that its version is adequate.

=item path => \@path

A list of directories where to look for commands. By default the
backend will relly on the shell using C<$PATH> in order to find them.

=item ${cmd}_cmd => $cmd_path

The path for some given command can be declared in this way. For
instance, if the C<netcat> command is installed in some custom place
the following argument can be passed:

  netcat_cmd => '/usr/local/netcat/bin/nc'

=item ${backend}_${entry} => $data

backend private arguments can be passed in that way.

=back

=head2 Backends

The backends currently available are as follows:

=over 4

=item netcat

Uses C<netcat> to open a connection to the remote server.

There are several C<netcat> implementations available and even if most
of them try to remain compatible with the original one, there may be
suttle differences between then that could cause this backend to
fail. If you believe this is happening with your particular C<netcat>,
please report it!

In any case, it has a preference for the the OpenBSD netcat version.

This backend can handle up to two HTTP or/and SOCKS4/5 proxies. It
does not support SSL.

=item socat

Uses C<socat> to open a connection to the remote server.

This backend support crossing one HTTP or SOCKS4 proxy. It does not
support SSL.

=item socat2

Uses C<socat> version 2 (still in beta) to connect to the remote
server.

This backend supports any combination of HTTP, SOCKS4, SOCKS5 and SSL
proxies.

=item ncat

Uses C<ncat> command (distributed as part of the nmap package) to
connect to the remote host.

Note than versions of this older than 5.22 were buggy and cause SSH
session to stall.

This backend supports one HTTP or SOCKS4 proxy. It does not support
SSL.

=item proxytunnel

This backend uses the C<proxytunnel> command in order to connect to
the remote server.

It supports up to two HTTP proxies and SSL and can handle NTLM
authentication.

This module accepts the following extra options:

=over 4

=item ntlm => $bool

Use NTLM for authentication on the proxies instead of the basic method.

=item quiet => $bool

=item verbose => $bool

Control the verbosity of C<proxytunnel>.

=item passfile => $path

Path to file containing the proxy authentication credentials.

=item domain => $domain

Domain for NTLM authentication.

=item header => $headers

Extra headers to send to the proxy.

=item proctitle => $title

Sets the proxy title.

=back

=item ssh_w

This backend uses the tunnel support available from recent versions of
OpenSSH through the C<-w> flag.

It allows to stablish a connection through an SSH gateway without
running any command on the gateway, but it requires tunnels to be
administratively enabled there (something that doesn't happen
frequently).

=item perl

This backend uses one perl one-liner to connect to the remote host. It
is useful to cross through SSH gateways were you will not find any
C<netcat> or similar program, but perl is usually included with the OS.

=back

=head1 SEE ALSO

L<Net::OpenSSH>.

=head1 COPYRIGHT AND LICENSE

Copyright (C) 2011 by Salvador Fandino E<lt>sfandino@yahoo.comE<gt>

This library is free software; you can redistribute it and/or modify
it under the same terms as Perl itself, either Perl version 5.12.4 or,
at your option, any later version of Perl 5 you may have available.

=cut
