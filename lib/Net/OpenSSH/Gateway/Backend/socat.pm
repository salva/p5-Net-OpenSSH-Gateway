package Net::OpenSSH::Gateway::Backend::socat;

use strict;
use warnings;

require Net::OpenSSH::Gateway::Backend;
our @ISA = qw(Net::OpenSSH::Gateway::Backend);

my %scheme2pproto = ( http => 'PROXY',
                      socks4 => 'SOCKS4' );

sub _command_version_args { '-V' }

sub _check_command_version_output {
    my ($self, $text) = @_;
    if (my ($ver) = $text =~ /^socat version (\S+)/m) {
        $self->{socat_version} = $ver;
        $self->{socat_version_number} = $self->_version_to_number($ver);
        $self->{socat_ssl} = 1 if $text =~ /#define\s+WITH_OPENSSL/;
        # print "socat version $ver found\n";
        return 1
    }
    return
}

sub check_args {
    my $self = shift;
    my $proxies = $self->{proxies};
    if (@$proxies > 1) {
        $self->_push_error("socat version 1 can not handle more than one proxy");
        return;
    }
    for my $proxy (@{$self->{proxies}}) {
        my $scheme = $proxy->{scheme};
        unless (defined $scheme2pproto{$scheme}) {
            $self->_push_error("socat version 1 does not support $proxy->{scheme} proxies");
            return;
        }
        if ($proxy->{ssl}) {
            $self->_push_error("socat version 1 does not support connecting to proxies with SSL");
            return;
        }
        if ($scheme eq 'socks4' and defined $proxy->{password}) {
            $self->_push_error("socks4 does not support password authentication");
            return;
        }
    }
    1;
}

sub _command_args {
    my ($self, %opts) = @_;

    my $arg;
    my $host = $self->_slave_quote_opt(host => %opts);
    my $port = $self->_slave_quote_opt(port => %opts);
    if (my $proxy = $self->{proxies}[0]) {
        my $proto = $self->_slave_quote($scheme2pproto{$proxy->{scheme}});
        $arg = join(":",
                    $proto,
                    $self->_slave_quote($proxy->{host}),
                    $host, $port);
        $arg .= "," . ($proto eq 'PROXY' ? 'proxyport' : 'socksport') . "=" . $self->_slave_quote($proxy->{port});

        my $auth = $proxy->{user};
        if (defined $auth) {
            if ($proto eq 'PROXY') {
                $arg .= ",proxyauth=";
                $auth .= ":$proxy->{password}" if defined $proxy->{password};
            }
            else {
                $arg .= ",socksuser=";
            }
            $arg .= $self->_slave_quote("$auth");
        }
    }
    else {
        $arg = "TCP4:$host:$port";
    }
    return ('-', $arg);
}

1;
