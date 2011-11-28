package Net::OpenSSH::Gateway::Backend::ncat;

use strict;
use warnings;

require Net::OpenSSH::Gateway::Backend;
our @ISA = qw(Net::OpenSSH::Gateway::Backend);

sub _default_command_names {
    { netcat => [qw(nc.openbsd nc netcat)] }
}

sub _command { 'ncat' }

sub _command_version_args { '-h' }

sub _check_command_version_output {
    my ($self, $out) = @_;
    $out =~ /OpenBSD netcat/ and return 1;
    undef;
}

my %scheme2pproto = ( http => 'http',
                      socks4 => 'socks4' );

sub check_args {
    my $self = shift;
    my $proxies = $self->{proxies};
    if (@$proxies > 1) {
        $self->_push_error("ncat can not handle more than one proxy");
        return;
    }
    for my $proxy (@$proxies) {
        unless ($scheme2pproto{$proxy->{scheme}}) {
            $self->_push_error("ncat does not support $proxy->{scheme} proxies");
            return;
        }
        if (defined $proxy->{password}) {
            $self->_push_error("ncat does not support password authentication for proxy access");
            return;
        }
    }
    1;
}

sub _command_args {
    my ($self, %opts) = @_;
    my @args;
    for my $proxy (@{$self->{proxies}}) {
        push @args, '--proxy-type' => $scheme2pproto{$proxy->{scheme}}, '--proxy' => $proxy->{host} . ':' . $proxy->{port};
        my $proxy_user = $proxy->{user},
        if (defined $proxy_user) {
            $proxy_user .= ":$proxy->{password}" if defined $proxy->{password};
            push @args, '--proxy-auth' => $proxy_user;
        }
    }

    ( $self->_slave_quote(@args),
      $self->_slave_quote_opt(host => %opts),
      $self->_slave_quote_opt(port => %opts) )
}


1;
