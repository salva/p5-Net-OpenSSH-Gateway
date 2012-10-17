package Net::OpenSSH::Gateway::Backend::pnc;

use strict;
use warnings;

require Net::OpenSSH::Gateway::Backend;
our @ISA = qw(Net::OpenSSH::Gateway::Backend);

sub _command { 'perl' }

sub check_args {
    my $self = shift;
    unless ($self->{via_ssh}) {
        $self->_push_error("using pnc does not make sense without via_ssh");
        return;
    }
    my $proxies = $self->{proxies};
    if (@$proxies) {
        $self->_push_error("pnc does not support proxies");
        return;
    }
    1;
}

sub _remote_pnc {
    my $self = shift;
    my $cmd = $self->{private}{remote_pnc};
    defined $cmd ? $cmd : ".pnc.pl";
}

sub _command_args {
    my ($self, %opts) = @_;

    my $host = $self->_slave_quote_opt(host => %opts);
    my $port = $self->_slave_quote_opt(port => %opts);

    my $remote_pnc = $self->_slave_quote($self->_remote_pnc);
    return ($remote_pnc, $host, $port);
}

sub before_ssh_connect {
    my $self = shift;
    if (my $ssh = $self->{via_ssh}) {
        require App::pnc;
        unless ($ssh->scp_put($INC{"App/pnc.pm"}, $self->_remote_pnc)) {
            $self->_push_error("scp failed", $ssh->error);
            return;
        }
    }
    $self->SUPER::before_ssh_connect;
}

1;
