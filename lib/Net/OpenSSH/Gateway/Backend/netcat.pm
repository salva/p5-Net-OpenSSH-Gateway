package Net::OpenSSH::Gateway::Backend::netcat;

use strict;
use warnings;

require Net::OpenSSH::Gateway::Backend;
our @ISA = qw(Net::OpenSSH::Gateway::Backend);

sub _command_names { qw(nc netcat) }

my %schema2pproto = ( http => 'connect',
                      socks4 => '4',
                      socks5 => '5' );

sub _command_args {
    my $self = shift;

    my @args;
    my $proxies = $self->{proxies};
    if (@$proxies > 1) {
        $self->_set_error("netcat can not handle more than one proxy");
        return;
    }
    for my $proxy (@$proxies) {
        my $proto = $schema2pproto{$proxy->{schema}};
        unless (defined $proto) {
            $self->_set_error("netcat does not support $proxy->{schema} proxies");
            return;
        }

        if (defined $proxy->{password}) {
            $self->_set_error("netcat does not support password authentication for proxy access");
            return;
        }

        push @args, -X => $proto, -x => $proxy->{host} . ':' . $proxy->{port};
        push @args, -P => $proxy->{user} if defined $proxy->{user};
    }

    push @args, $self->{host}, $self->{port};
    return @args;
}

1;
