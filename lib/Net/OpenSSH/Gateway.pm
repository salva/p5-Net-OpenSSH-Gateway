package Net::OpenSSH::Gateway;

our $VERSION = '0.01';

use 5.010;
use strict;
use warnings;
use Carp;
use Fcntl qw(F_GETFL F_SETFL O_NONBLOCK);

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
# Below is stub documentation for your module. You'd better edit it!

=head1 NAME

Net::OpenSSH::Gateway - Perl extension for blah blah blah

=head1 SYNOPSIS

  use Net::OpenSSH::Gateway;
  blah blah blah

=head1 DESCRIPTION

Stub documentation for Net::OpenSSH::Gateway, created by h2xs. It looks like the
author of the extension was negligent enough to leave the stub
unedited.

Blah blah blah.

=head2 EXPORT

None by default.



=head1 SEE ALSO

Mention other useful documentation such as the documentation of
related modules or operating system documentation (such as man pages
in UNIX), or any relevant external documentation such as RFCs or
standards.

If you have a mailing list set up for your module, mention it here.

If you have a web site set up for your module, mention it here.

=head1 AUTHOR

Salvador Fandino, E<lt>salva@E<gt>

=head1 COPYRIGHT AND LICENSE

Copyright (C) 2011 by Salvador Fandino

This library is free software; you can redistribute it and/or modify
it under the same terms as Perl itself, either Perl version 5.12.4 or,
at your option, any later version of Perl 5 you may have available.


=cut
