package Net::OpenSSH::Gateway::Backend::pnc;

use strict;
use warnings;

require Net::OpenSSH::Gateway::Backend;
our @ISA = qw(Net::OpenSSH::Gateway::Backend);

sub _command { 'perl' }

sub _command_version_args { '-V' }

sub _check_command_version_output {
    my ($self, $text) = @_;
    if (my ($ver) = $text =~ /^pnc\s+(\S+)/m) {
        $self->{pnc_version} = $ver;
        $self->{pnc_version_number} = $self->_version_to_number($ver);
        return 1;
    }
    return;
}

sub check_args {
    my $self = shift;
    my $proxies = $self->{proxies};
    if (@$proxies) {
        $self->_push_error("pnc does not support proxies");
        return;
    }
    1;
}

sub _command_args {
    my ($self, %opts) = @_;

    my $host = $self->_slave_quote_opt(host => %opts);
    my $port = $self->_slave_quote_opt(port => %opts);

    return ($host, $port);
}

sub _before_ssh_connect {
    
}

sub _after_ssh_connect {

}

1;
