package Net::OpenSSH::Gateway::Backend::perl;

use strict;
use warnings;

require Net::OpenSSH::Gateway::Backend;
our @ISA = qw(Net::OpenSSH::Gateway::Backend);

sub _command { 'perl' }

my @data = <DATA>;
my $data = join('', @data);

sub check_args {
    my $self = shift;
    for my $proxy (@{$self->{proxies}}) {
        my $scheme = $proxy->{scheme};
        unless ($scheme =~ /^socks4a?$/) {
            $self->_push_error("pnc does not support '$scheme' proxies");
            return;
        }
        if ($proxy->{ssl}) {
            $self->_push_error("pnc does not support connecting to proxies with SSL");
            return;
        }
        if (defined $proxy->{password}) {
            $self->_push_error("socks4 does not support password authentication");
            return;
        }
    }
    1;
}

#Fcntl  => [qw(F_SETFL F_GETFL O_NONBLOCK)] );

sub _command_args {
    my ($self, %opts) = @_;

    my %modules = ( 'IO::Socket::INET' => [] );
    my @cmd_args;
    my $connect_code = '';
    my $proxy_code = '';

    my $pack_tmpl = '';
    my @pack_args;

    my $before;
    for my $proxy (@{$self->{proxies}}, undef) {
        my ($host, $port);
        if ($proxy) {
            $port = $self->_slave_quote($proxy->{port});
            $host = $self->_slave_quote($proxy->{host});
        }
        else {
            $host = $self->_slave_quote_opt(host => %opts);
            $port = $self->_slave_quote_opt(port => %opts);
        }
        if ($before) {
            my $scheme = $before->{scheme};
            my $user = $before->{user};
            if ($scheme =~ /^socks4a?$/) {
                my $upper_bits = 0x4010000;
                my $t1;
                if ($port =~ /^\d+$/) {
                    $t1 = $upper_bits|$port
                }
                else {
                    $t1 = $upper_bits.'|shift';
                    push @cmd_args, $port;
                }
                $pack_tmpl .= 'N';
                push @pack_args, $t1;
                if ($host =~ /^\d+\.\d+\.\d+\.\d+$/) {
                    require Socket;
                    my $addr = Socket::inet_aton($host);
                    unless (defined $addr) {
                        $self->_push_error("bad IP address '$host'");
                        return;
                    }
                    my $t2 = unpack N => $addr;
                    if (defined $user) {
                        $pack_tmpl .= 'NZ*';
                        push @pack_args, $t2, 'shift';
                        push @cmd_args, $user;
                    }
                    else {
                        $pack_tmpl .= 'NC';
                        push @pack_args, $t2, 0;
                    }
                }
                elsif ($scheme eq 'socks4') {
                    $modules{Socket} = [];
                    my $t2 = "inet_aton(shift)";
                    push @cmd_args, $host;
                    if (defined $user) {
                        $t2 .= '.shift';
                        push @cmd_args, $user;
                    }
                    $pack_tmpl .= 'Z*';
                    push @pack_args, $t2
                }
                else { # socks4a
                    my $t2;
                    if (defined $user) {
                        $pack_tmpl .= 'NZ*Z*';
                        push @cmd_args, $user, $host;
                        push @pack_args, 1, 'shift', 'shift';
                    }
                    else {
                        $pack_tmpl .= 'NCZ*';
                        push @cmd_args, $host;
                        push @pack_args, 1, 0, 'shift';
                    }
                }
            }
            else {
                $self->_push_error("proxy schema $scheme not supported");
                return;
            }
        }
        else {
            push @cmd_args, "${host}:${port}";
            $connect_code = '$socket = new IO::Socket::INET shift;'
        }
        $before = $proxy;
    }

    if (my $n = @{$self->{proxies}}) {
        $proxy_code = join("\n",
                           'print $socket pack("'.$pack_tmpl.'", '.join(',', @pack_args).');',
                           'sysread $socket, $pb, 1, $_ for 0..' . ($n * 8 - 1) . ';',
                           '$pb =~ ' .(($n == 1) ? '/^.\x5a/' : '/^(.\x5a.{6}){'.$n.'}/s') . '||exit;');
    }

    my $code = $data;
    $code =~ s/ALARM_CODE;/alarm $self->{timeout};/;
    $code =~ s/CONNECT_CODE;/$connect_code/;
    $code =~ s/PROXY_CODE;/$proxy_code/;
    $code = $self->_slave_quote($self->_minify_code($code));

    my @modules;
    for my $k (keys %modules) {
        push @modules, "-M$k" . (@{$modules{$k}} ? '=' . join(',', @{$modules{$k}}) : '')
    }

    return (@modules, "-e$code", @cmd_args);
}

sub _minify_code {
    my ($self, $code) = @_;
    if (1) {
        $code =~ s/^#.*$//m;
        $code =~ s/\s+/ /g;
        $code =~ s/\s(?!\w)//g; # that breaks "use foo 'doz'" so don't use that!!!
        $code =~ s/(?<!\w)\s//g;
        $code =~ s/;}/}/g;

        my $next = 'c';
        my %vars;
        $code =~ s/([\$\@%])([a-z]\w*)/$1 . ($vars{$2} ||= $next++)/ge;
    }
    $code;
}

1;

__DATA__
$0=perl;
ALARM_CODE;
CONNECT_CODE;
PROXY_CODE;
alarm 0;
blocking $_ 0 for @in = (*STDIN, $socket), @out = ($socket, *STDOUT);

L:
for (0, 1) {
    sysread ($in[$_], $buffer, 8**5) || exit and $buffer[$_] .= $buffer
        if vec $iv, $_ * ($socket_fileno = fileno $socket), 1;
    substr $buffer[$_], 0, syswrite($out[$_], $buffer[$_], 8**5), "";
    vec($iv, $_ * $socket_fileno, 1) = ($l = length $buffer[$_] < 8**5);
    vec($ov, $_ || $socket_fileno, 1) = !!$l;
}
select $iv, $ov, $u, 5;
goto L

