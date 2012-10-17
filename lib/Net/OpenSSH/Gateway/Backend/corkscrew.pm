package Net::OpenSSH::Gateway::Backend::corkscrew;

use strict;
use warnings;

require Net::OpenSSH::Gateway::Backend;
our @ISA = qw(Net::OpenSSH::Gateway::Backend);

sub _command { 'corkscrew' }

sub _command_version_args { }

sub _check_command_version_output {
    my ($self, $text) = @_;
    if (my ($ver) = $text =~ /corkscrew\s+(\S+)/m) {
        $self->{corkscrew_version} = $ver;
        $self->{corkscrew_version_number} = $self->_version_to_number($ver);
        return 1;
    }
    return;
}

sub check_args {
    my $self = shift;
    my $proxies = $self->{proxies};
    if (@$proxies != 1 or $proxies->[0]{scheme} ne 'http') {
        $self->_push_error("corkscrew can handle connections going through a single HTTP proxy only");
        return;
    }
    1;
}

sub _command_args {
    my ($self, %opts) = @_;
    my $proxy = $self->{proxies}[0];
    return ( map($self->_slave_quote($proxy->{$_}), qw(host port)),      # proxy
             map($self->_slave_quote_opt($_ => %opts), qw(host port)) ); # target host
}

1;
