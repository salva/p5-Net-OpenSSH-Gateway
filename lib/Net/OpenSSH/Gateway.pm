package Net::OpenSSH::Gateway;

our $VERSION = '0.01';

use 5.010;
use strict;
use warnings;
use Carp;
use Fcntl qw(F_GETFL F_SETFL O_NONBLOCK);

my @default_backends = qw(w netcat nc socat pnc);

sub _array_or_scalar_to_list { map { defined($_) ? (ref $_ eq 'ARRAY' ? @$_ : $_ ) : () } @_ }

sub new {
    my $class = shift;
    @_ & 1 and unshift @_, 'ssh';
    my %opts = @_;
    my $ssh = delete $opts{ssh} // croak "required argument ssh missing";
    my $timeout = delete $opts{ssh} // $ssh->{_timeout} // 60;
    my @backends = _array_or_scalar_to_list( delete $opts{backend} //
                                             delete $opts{backends} //
                                             \@default_backends);
    my $self = { ssh => $ssh,
                 backends => \@backends,
                 cache => {},
                 timeout => $timeout };
    bless $self, $class;
}

sub make_proxy_command {
    my $self = shift;
    @_ & 1 and unshift @_, 'host';
    my %opts = @_;
    my $conn = $self->{ssh}->parse_connection_opts(\%opts);
    my $host = delete $conn->{host};
    my $port = delete $conn->{port} // 22;
    my $ipv6 = delete $conn->{ipv6} and croak "IPv6 not supported yet";
    my $key = "$host:$port";

    for my $backend (@{$self->{backends}}) {
        my $proxy_cmd = $self->{cache}{$backend}{$key};
        return $proxy_cmd if defined $proxy_cmd;
        my $sub = $self->can("_make_proxy_command__$backend");
        defined $sub or croak "unknown backend $backend";
        my ($opts, @cmd) = $sub->($self, $host, $port);
        if ($self->_check_proxy($opts, @cmd)) {
            return $self->{cache}{$backend}{$key} =
                $self->{ssh}->make_remote_command($opts, @cmd);
        }
    }
    ();
}

sub _check_proxy {
    my ($self, $opts, @cmd) = @_;
    my ($s, $pid) = $self->{ssh}->open2socket($opts, @cmd) or return;
    fcntl($s, F_SETFL, fcntl($s, F_GETFL, 0) | O_NONBLOCK);
    binmode $s;
    my $timeout = $self->{timeout};
    my $buffer = '';
    my $time_limit = time + $timeout;
    while (1) {
        my $iv = '';
        vec($iv, fileno($s), 1) = 1;
        if (select($iv, undef, undef, 1) > 0) {
            sysread($s, $buffer, 1000, length $buffer) or last;
            $buffer =~ /\x0d\x0a/ and last;
        }
        last if time > $time_limit or length $buffer > 2000;
    }

    close $s;
    $self->{ssh}->_waitpid($pid, $self->{$timeout});

    return scalar($buffer =~ /^SSH.*\x0d\x0a/)
}

sub _make_proxy_command__w {
    my ($self, $host, $port) = @_;
    return ({ tunnel => 1 }, $host, $port);
}

sub _make_proxy_command__netcat {
    my ($self, $host, $port) = @_;
    return ({}, 'netcat', $host, $port);
}

1;
__END__
# Below is stub documentation for your module. You'd better edit it!

=head1 NAME

Net::OpenSSH::Gateway - Perl extension for blah blah blah

=head1 SYNOPSIS

  use Net::OpenSSH::Gateway;
  blah blah blah

=head1 DESCRIPTION

Stub documentation for Net::OpenSSH::Gateway, created by h2xs. It looks like the
author of the extension was negligent enough to leave the stub
unedited.

Blah blah blah.

=head2 EXPORT

None by default.



=head1 SEE ALSO

Mention other useful documentation such as the documentation of
related modules or operating system documentation (such as man pages
in UNIX), or any relevant external documentation such as RFCs or
standards.

If you have a mailing list set up for your module, mention it here.

If you have a web site set up for your module, mention it here.

=head1 AUTHOR

Salvador Fandino, E<lt>salva@E<gt>

=head1 COPYRIGHT AND LICENSE

Copyright (C) 2011 by Salvador Fandino

This library is free software; you can redistribute it and/or modify
it under the same terms as Perl itself, either Perl version 5.12.4 or,
at your option, any later version of Perl 5 you may have available.


=cut
