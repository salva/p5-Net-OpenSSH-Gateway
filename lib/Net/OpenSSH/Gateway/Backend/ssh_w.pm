package Net::OpenSSH::Gateway::Backend::ssh_w;

use strict;
use warnings;
use Carp;

require Net::OpenSSH::Gateway::Backend;
our @ISA = qw(Net::OpenSSH::Gateway::Backend);

sub check_args {
    my $self = shift;
    my $ssh = $self->{via_ssh};
    unless ($ssh) {
        $self->_push_error("ssh_w backend requires via_ssh to be defined");
        return;
    }
    if (@{$self->{proxies}}) {
        $self->_push_error("ssh_w backend does not supports proxies");
        return;
    }
    1;
}

sub proxy_command {
    my $self = shift;
    $self->check_args or return;
    my %opts = $self->_parse_connection_opts(@_);
    my $ssh = $self->{via_ssh};
    return scalar $self->{via_ssh}->make_remote_command({tunnel => 1},
                                                        $self->_slave_quote_opt(host => %opts),
                                                        $self->_slave_quote_opt(port => %opts));
}

1;
