package Net::OpenSSH::Gateway::Backend::perl;

use strict;
use warnings;

require Net::OpenSSH::Gateway::Backend;
our @ISA = qw(Net::OpenSSH::Gateway::Backend);

sub _command { 'perl' }

my @data = <DATA>;
my $data = join('', @data);

sub check_args {
    my $self = shift;
    my $proxies = $self->{proxies};
    if (@$proxies) {
        $self->_push_error("pnc does not support proxies");
        return;
    }
    1;
}

my %modules = ( Socket => [],
                Fcntl  => [qw(F_SETFL F_GETFL O_NONBLOCK)],
                Errno  => [qw(ENOTSOCK)] );

sub _command_args {
    my ($self, %opts) = @_;

    my $code = $self->_slave_quote($self->_minify_code($data));

    my $host = $self->_slave_quote_opt(host => %opts);
    my $port = $self->_slave_quote_opt(port => %opts);
    $code =~ s/\bPORT\b/$port/g;
    $code =~ s/\bSERVER\b/$host/g;

    my @modules;
    for my $k (keys %modules) {
        push @modules, "-M$k" . (@{$modules{$k}} ? '=' . join(',', @{$modules{$k}}) : '')
    }

    return (@modules, -e => $code);
}

sub _minify_code {
    my ($self, $code) = @_;
    if (0) {
        $code =~ s/^#.*$//m;
        $code =~ s/\s+/ /g;
        $code =~ s/\s(?!\w)//g; # that breaks "use foo 'doz'" so don't use that!!!
        $code =~ s/(?<!\w)\s//g;
        $code =~ s/;}/}/g;

        my $next = 'c';
        my %vars;
        $code =~ s/([\$\@%])([a-z]\w*)/$1 . ($vars{$2} ||= $next++)/ge;
    }
    $code;
}

sub _generate_pnc {
    my $self = shift;

    open (my $out, ">/tmp/pnc") or die $!;

    print $out "#!/usr/bin/perl\n";
    print $out "use $_" . (@{$modules{$_}} ? " qw(@{$modules{$_}})" : '') .";\n" for keys %modules;
    my $code = $self->_minify_code($data);
    $code =~ s/\bSERVER\b/\$ARGV[0]/;
    $code =~ s/\bPORT\b/\$ARGV[1]/;
    print $out "$code\n";
    close $out;
}

__DATA__

use Socket;
use Carp;
use Fcntl qw(F_GETFL F_SETFL O_NONBLOCK);
use Errno qw(ENOTSOCK);

use strict;
use warnings;
no warnings "uninitialized";

my ($socket, @in, @out, @buffer, @in_open, @out_open);

( socket($socket, AF_INET, SOCK_STREAM, 0) &&
  connect($socket,  sockaddr_in(PORT, inet_aton("SERVER"))) ) || die $!;

@in = (*STDIN, $socket);
@out = ($socket, *STDOUT);

fcntl($_, F_SETFL, fcntl($_, F_GETFL, 0)|O_NONBLOCK) for @in, @out;

@in_open= (1, 1);
@out_open = (1, 1);

$SIG{PIPE} = "IGNORE";

sub _shutdown {
    my ($socket, $dir) = @_;
    unless (shutdown($socket, $dir)) {
        if ($! == ENOTSOCK) {
            return close ($socket);
        }
    }
    undef;
}

while (grep $_, @in_open, @out_open) {
    my ($iv, $ov);
    for my $ix (0, 1) {
        if ($in_open[$ix] and length $buffer[$ix] < 50000) {
            vec($iv, fileno($in[$ix]), 1) = 1;
        }
        if ($out_open[$ix] and length $buffer[$ix] > 0) {
            vec($ov, fileno($out[$ix]), 1) = 1;
        }
    }
    if (select($iv, $ov, undef, 5) > 0) {
        for my $ix (0, 1) {
            if ($in_open[$ix] and vec($iv, fileno($in[$ix]), 1)) {
                sysread($in[$ix], $buffer[$ix], 16 * 1024, length $buffer[$ix]) || exit;
            }
            if ($out_open[$ix] and vec($ov, fileno($out[$ix]), 1)) {
                substr $buffer[$ix], 0, syswrite($out[$ix], $buffer[$ix], 16 * 1024) || exit, "";
            }
        }
    }
}
