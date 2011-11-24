package Net::OpenSSH::Gateway::Backend::netcat;

use strict;
use warnings;

require Net::OpenSSH::Gateway::Backend;
our @ISA = qw(Net::OpenSSH::Gateway::Backend);

sub _default_command_names {
    { netcat => [qw(nc.openbsd nc netcat)] }
}

sub _command { 'netcat' }

sub _command_version_args { '-h' }

sub _check_command_version_output {
    my ($self, $out) = @_;
    $out =~ /OpenBSD netcat/ and return 1;
    undef;
}

my %scheme2pproto = ( http => 'connect',
                      socks4 => '4',
                      socks5 => '5' );

sub check_args {
    my $self = shift;
    my $proxies = $self->{proxies};
    if (@$proxies > 1) {
        $self->_set_error("netcat can not handle more than one proxy");
        return;
    }
    for my $proxy (@$proxies) {
        unless ($scheme2pproto{$proxy->{scheme}}) {
            $self->_set_error("netcat does not support $proxy->{scheme} proxies");
            return;
        }
        if (defined $proxy->{password}) {
            $self->_set_error("netcat does not support password authentication for proxy access");
            return;
        }
    }
    1;
}

sub _command_args {
    my ($self, %opts) = @_;
    my @args;
    for my $proxy (@{$self->{proxies}}) {
        push @args, -X => $scheme2pproto{$proxy->{scheme}}, -x => $proxy->{host} . ':' . $proxy->{port};
        push @args, -P => $proxy->{user} if defined $proxy->{user};
    }
    @args, $opts{host}, $opts{port};
}


1;
