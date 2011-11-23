package Net::OpenSSH::Gateway::Backend::ssh_w;

use strict;
use warnings;
use Carp;

require Net::OpenSSH::Gateway::Backend;
our @ISA = qw(Net::OpenSSH::Gateway::Backend);

sub proxy_command {
    my $self = shift;
    my $ssh = $self->{via_ssh};
    unless ($ssh) {
        $self->_set_error("ssh_w backend requires via_ssh to be defined");
        return;
    }
    if (@{$self->{proxies}}) {
        $self->_set_error("ssh_w backend does not supports proxies");
        return;
    }
    return scalar $ssh->make_remote_command({tunnel => 1}, $self->{host}, $self->{port});
}

1;
