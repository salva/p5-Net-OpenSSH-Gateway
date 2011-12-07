package Net::OpenSSH::Gateway::Backend::socat2;

use strict;
use warnings;

require Net::OpenSSH::Gateway::Backend::socat;
our @ISA = qw(Net::OpenSSH::Gateway::Backend::socat);

my %scheme2pproto = ( http => 'proxy-connect',
                      socks4 => 'socks4',
                      socks5 => 'socks5',
                      ssl => 'openssl');

sub _command { 'socat' }

sub _command_version_args { '-V' }

sub _check_command_version_output {
    my $self = shift;
    if ($self->SUPER::_check_command_version_output(@_)) {
        #use Data::Dumper;
        #print Dumper $self;

        return 1 if $self->{socat_version_number} >= 2;
        $self->_push_error("socat2 backend requires socat 2.0.0 or later, version $self->{socat_version} found");
    }
    return;
}

sub check_args {
    my $self = shift;
    for my $proxy (@{$self->{proxies}}) {
        my $scheme = $proxy->{scheme};
        $scheme =~ s/s$//;
        unless (defined $scheme2pproto{$scheme}) {
            $self->_push_error("socat does not support $proxy->{scheme} proxies");
            return;
        }
    }
    1;
}

sub _command_args {
    my ($self, %opts) = @_;

    my @chain;
    my $host = $self->_slave_quote_opt(host => %opts);
    my $port = $self->_slave_quote_opt(port => %opts);
    for my $proxy (reverse @{$self->{proxies}}) {
        my $scheme = $proxy->{scheme};
        if ($scheme eq 'ssl') {
            push @chain, 'openssl';
        }
        else {
            $scheme =~ s/s$//;
            my $proto = $self->_slave_quote($scheme2pproto{$scheme});
            push @chain, "$proto:$host:$port";
            $proxy->{ssl} and push @chain, 'openssl';
            $host = $self->_slave_quote($proxy->{host});
            $port = $self->_slave_quote($proxy->{port});
        }
    }
    push @chain, "tcp:$host:$port";
    return ('-', join('|', @chain));
}

1;
