package Net::OpenSSH::Gateway::Backend::proxytunnel;

use strict;
use warnings;

require Net::OpenSSH::Gateway::Backend;
our @ISA = qw(Net::OpenSSH::Gateway::Backend);

my %scheme2pproto = ( http => 'proxy-connect' );

sub _command { 'proxytunnel' }

sub _command_version_args { '-V' }

sub _check_command_version_output {
    my ($self, $text) = @_;
    if (my ($ver) = $text =~ /^proxytunnel\s+(\S+)/m) {
        $self->{proxytunnel_version} = $ver;
        $self->{proxytunnel_version_number} = $self->_version_to_number($ver);
        return 1;
    }
    return;
}

sub check_args {
    my $self = shift;
    my $proxies = $self->{proxies};
    if (@$proxies > 2) {
        $self->_push_error("proxytunnel can not handle more than two proxies");
        return;
    }
    for my $proxy (@$proxies) {
        unless ($proxy->{scheme} =~ /^https?$/) {
            $self->_push_error("proxytunnel can not handle $proxy->{scheme} proxies");
            return;
        }
    }
    1;
}

my %flags = ( ntlm     => 'N',
              quiet    => 'q',
              verbose  => 'v'
            );

my %kv    = ( passfile  => 'F',
              domain    => 't',
              header    => 'H',
              proctitle => 'x' );

sub _command_args {
    my ($self, %opts) = @_;

    my @args;
    my $proxies = $self->{proxies};
    for my $pix (0 .. $#$proxies) {
        my $proxy = $proxies->[$pix];
        my $auth = $proxy->{user};
        if (defined $auth) {
            $auth .= $proxy->{password}  if defined $proxy->{password};
            push @args, (qw(-P -R))[$pix], $self->_slave_quote($auth);
        }
        push @args, (qw(-E -X))[$pix] if $proxy->{ssl};
        push @args, (qw(-p -r))[$pix], $self->_slave_quote("$proxy->{host}:$proxy->{port}");
    }

    for my $k (keys %flags) {
        push @args, "-$flags{$k}" if $self->{private}{$k};
    }
    for my $k (keys %kv) {
        push @args, "-$kv{$k}", $self->_slave_quote($self->{private}{$k})
            if defined $self->{private}{$k};
    }

    my $host = $self->_slave_quote_opt(host => %opts);
    my $port = $self->_slave_quote_opt(port => %opts);

    return (@args, -d => "$host:$port");
}

1;
