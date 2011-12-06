package Net::OpenSSH::Gateway;

our $VERSION = '0.01';

use 5.010;
use strict;
use warnings;
use Carp;
use Fcntl qw(F_GETFL F_SETFL O_NONBLOCK);

my @default_backends = qw(ssh_w netcat socat socat2 ncat perl pnc);

sub find_gateway {
    my $class = shift;
    my %opts = (@_ & 1 ? (host => @_) : @_);
    my $errors;
    if (exists $opts{errors}) {
        for (my $i = (@_ & 1); $i < @_; $i += 2) {
            if ($_[$i] eq 'errors') {
                local ($SIG{__DIE__}, $@);
                eval { $errors = ($_[$i+1] ||= []) };
                last;
            }
        }
        ref $errors eq 'ARRAY'
            or croak "errors argument must be an array reference or an unitialized variable";
    }
    else {
        $errors = [];
    }
    @$errors = ();

    $opts{check} = 1 unless defined $opts{check};
    my $check = $opts{check};

    my $backends = delete $opts{backends};
    $backends = delete $opts{backend} unless defined $backends;
    $backends = \@default_backends unless defined $backends;
    my @backends = (ref $backends ? @$backends : $backends);
    croak "bad backend name $_" for grep !/\w/, @backends;

    for my $backend (@backends) {
        my $class = __PACKAGE__ . '::Backend::' . $backend;
        unless(eval "require $class; 1") {
            push @$errors, "unable to load backend $class: $@";
            next;
        };
        my $gateway = $class->new(%opts);
        if ($gateway->check_args and
            (!$check or $gateway->check)) {
            return $gateway
        }
        push @$errors, $gateway->errors;
    }
    push @$errors, "no suitable backend found";
    ()
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
