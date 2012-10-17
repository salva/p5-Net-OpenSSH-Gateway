package Net::OpenSSH::Gateway::Backend::sshd_i_ssh_w;

require Net::OpenSSH::Gateway::Backend::ssh_w;
our @ISA = qw(Net::OpenSSH::Gateway::Backend::ssh_w);

use strict;
use warnings;
use Carp;

my %keys = ( private => <<EOK,
-----BEGIN RSA PRIVATE KEY-----
MIIBygIBAAJhAMFU3sRo+wzkS+tEB/njsDJmLrNSsvERahiLdVNdvWKzezVZXYsg
/7bppJp679w+wOyme4c5PgVu78FoMTpAtAhjjodFWLWhEWlTgfw69ef/oki/nypl
zse7n8nSBHdsgwIDAQABAmAkGIBvE1qsEYPLLSyAD266OjHF8U7Pi3zPkFobcokF
gJUkZMb+Tu7va7f7z7Aw4tY3RdpRHaAmnRqBRpxa4pOnlnEiYq50wDs6VYIv0yoX
YuQroxkVqjx6v02EBztjTuECMQDfvE5/uIW6BvDlzVNxjAD+vs2YCo+ZGtIt1m5u
Afwafq7+5KEXmAvTdJPcMhy+nW0CMQDdNiGAhB/lB7tFsoQKK/wNMsGWMKRNAcUp
kGW1cZeVfwjpIMXRyvR6A8Ggsz/Kq68CMAd9dFtOQBvUM6hd0VdRyo68sIFQiTIk
9bhXH2dLZbc1WoJqAQKbMnonwvNyMggnmQIxANTsx66WfsTLfl0GCcZotAJYOrJA
O8XL0GXDkcLmhcvmLUOIwiC/xDa16uit4NdKDQIwcK+HyEXO3IBlyqCQExK0Ja+G
kIxvwtD41FTBC2oWxnFWluaMD7L+pzLzhZ/NYsJW
-----END RSA PRIVATE KEY-----
EOK
             public => <<EOK );
ssh-rsa AAAAB3NzaC1yc2EAAAADAQABAAAAYQDBVN7EaPsM5EvrRAf547AyZi6zUrLxEWoYi3VTXb1is3s1WV2LIP+26aSaeu/cPsDspnuHOT4Fbu/BaDE6QLQIY46HRVi1oRFpU4H8OvXn/6JIv58qZc7Hu5/J0gR3bIM=
EOK

sub _remote_key {
    my $self = shift;
    my $key = $self->{private}{remote_key};
    defined $key ? : ".libnet-openssh-gateway-key";
}

sub before_ssh_connect {
    my $self = shift;
    my $sftp = $self->_sftp or return;
    my $remote_key = $self->_remote_key;
    $sftp->_put_content($keys{$_}, "$remote_key.$_")
        or return
            for keys %keys;
    $self->SUPER::before_ssh_connect;
}

sub proxy_command {
    
    
}
