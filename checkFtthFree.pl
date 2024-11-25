#!/usr/bin/env perl
#
# checkFtthFree
# Copyright (C) 2023-2024 Yann Riou <yaribzh@gmail.com>
#
# This program is free software: you can redistribute it and/or modify
# it under the terms of the GNU Affero General Public License as published by
# the Free Software Foundation, either version 3 of the License, or
# (at your option) any later version.
#
# This program is distributed in the hope that it will be useful,
# but WITHOUT ANY WARRANTY; without even the implied warranty of
# MERCHANTABILITY or FITNESS FOR A PARTICULAR PURPOSE.  See the
# GNU Affero General Public License for more details.
#
# You should have received a copy of the GNU Affero General Public License
# along with this program.  If not, see <http://www.gnu.org/licenses/>.
#
# SPDX-License-Identifier: AGPL-3.0-or-later
#

use warnings;
use strict;

use utf8;

use Encode ();
use List::Util qw'any min sum0';
use Time::HiRes qw'time sleep';

use constant {
  LINUX => $^O eq 'linux',
  MSWIN32 => $^O eq 'MSWin32',
};

require HTTP::Tiny;
require Net::Ping;
{
  no warnings 'once';
  $Net::Ping::pingstring="PING\n";
}
require POSIX;
require Time::Piece;

my $VERSION='0.23';
my $PROGRAM_NAME='checkFtthFree';

my $IPV6_COMPAT=eval { require IO::Socket::IP; IO::Socket::IP->VERSION(0.25) };

my %TEST_DATA = ( 'local' => { IPv4 => ['212.27.38.253',8095,'/fixed/10G',2,10] },
                  Internet => { IPv4 => { download => { 12876 => { BBR => ['ipv4.scaleway.testdebit.info',80,'/10G.iso',10,30],
                                                                   CUBIC => ['ping.online.net',80,'/10000Mo.dat',10,30] },
                                                        5410 => { BBR => ['ipv4.paris.testdebit.info',80,'/10G.iso',10,30],
                                                                  CUBIC => ['ipv4.bouygues.testdebit.info',80,'/10G.iso',10,30] } },
                                          upload => { 12876 => ['ipv4.scaleway.testdebit.info',80,'',10,30],
                                                      5410 => ['ipv4.paris.testdebit.info',80,'',10,30] } },
                                IPv6 => { download => { 12876 => { BBR => ['ipv6.scaleway.testdebit.info',80,'/10G.iso',10,30],
                                                                   CUBIC => ['ping6.online.net',80,'/10000Mo.dat',10,30] },
                                                        5410 => { BBR => ['ipv6.paris.testdebit.info',80,'/10G.iso',10,30],
                                                                  CUBIC => ['ipv6.bouygues.testdebit.info',80,'/10G.iso',10,30] } },
                                          upload => { 12876 => ['ipv6.scaleway.testdebit.info',80,'',10,30],
                                                      5410 => ['ipv6.paris.testdebit.info',80,'',10,30] } },
                  } );
my %AS_NAMES = ( 5410 => 'Bouygues Telecom',
                 6799 => 'OTE',
                 12322 => 'Free',
                 12876 => 'Scaleway',
                 16276 => 'OVHcloud',
                 21409 => 'Ikoula',
                 24904 => 'Kwaoo K-Net',
                 53589 => 'PlanetHoster',
                 197133 => 'Mediactive Network',
                 200780 => 'Appliwave' );

my $MTU=1500;
my $MSS=$MTU-40;
my $TCP_EFFICIENCY=$MSS/($MTU+38);
my $GOODPUT_1Gbps_Bytes=1_000_000_000*$TCP_EFFICIENCY/8;
my $GOODPUT_700Mbps_Bytes=700_000_000*$TCP_EFFICIENCY/8;
my $RECOMMENDED_MIN_RTT_MAX_FOR_FULL_BANDWIDTH=15;
my $RECOMMENDED_MIN_RCV_WINDOW_SIZE=$GOODPUT_1Gbps_Bytes*$RECOMMENDED_MIN_RTT_MAX_FOR_FULL_BANDWIDTH/1000;
my $RECOMMENDED_MIN_SND_WINDOW_SIZE=$GOODPUT_700Mbps_Bytes*$RECOMMENDED_MIN_RTT_MAX_FOR_FULL_BANDWIDTH/1000;
my $TCP_WMEM_SND_WINDOW_RATIO=7/10;

my %cmdOpts=('check-update' => ['Effectue seulement la vérification de disponibilité de nouvelle version','c'],
             'skip-check-update' => ['Désactive la vérification de disponibilité de nouvelle version','C'],
             'skip-intro' => ["Désactive le message d'introduction et démarre immédiatement les tests",'I'],
             'net-conf' => ['Effectue seulement la lecture de la configuration réseau','n'],
             'skip-net-conf' => ['Désactive la lecture de la configuration réseau (empêche la détection de certains problèmes)','N'],
             suggestions => ['Affiche des suggestions pour résoudre des problèmes de configuration réseau ou compléter les tests si besoin','s'],
             freebox => ['Effectue seulement les tests locaux à partir de la Freebox (pas de test Internet)','f'],
             'skip-freebox' => ['Désactive les tests locaux à partir de la Freebox (tests Internet uniquement, empêche la détection de certains problèmes)','F'],
             latency => ['Effectue seulement les tests de latence (pas de test de débit)','l'],
             'skip-latency' => ['Désactive les tests de latence (tests de débit uniquement, empêche la détection de certains problèmes)','L'],
             upload => ['Effectue un test de débit montant au lieu de descendant (EXPERIMENTAL)','u'],
             'binary-units' => ["Utilise les préfixes binaires pour le système d'unités de débit",'b'],
             'extended-test' => ['Effectue des tests plus longs (multiplie par 2 la durée max des tests)','e'],
             'quiet' => ["Mode silencieux: désactive les messages d'analyse et d'avertissement",'q'],
             help => ["Affiche l'aide",'h'],
             version => ['Affiche la version','v'],
             ipv6 => ['Effectue les tests Internet en IPv6 (IPv4 par défaut)','6']);
my %cmdOptsAliases = map {$cmdOpts{$_}[1] => $_} (keys %cmdOpts);

my $httpClient=HTTP::Tiny->new(proxy => undef, http_proxy => undef, https_proxy => undef);

my ($WIN32_ACP_NB,$WIN32_OUTPUTCP);
if(MSWIN32) {
  require Win32;
  ($WIN32_ACP_NB,$WIN32_OUTPUTCP)=(Win32::GetACP(),'cp'.Win32::GetConsoleOutputCP());
  eval "use open ':std', OUT => ':encoding($WIN32_OUTPUTCP)'";
  if($@) {
    quit("Impossible de configurer l'encodage de la console Windows:\n$@");
  }
}else{
  eval "use open ':std', ':encoding(utf8)'";
}

sub win32PowershellExec {
  my $psCmd="powershell.exe \"$_[0]\" 2>NUL";
  my $previousCP=Win32::GetConsoleCP();
  Win32::SetConsoleCP($WIN32_ACP_NB); # Prevent powershell.exe from replacing current font when UTF-8 is used...
  my @res = map {Encode::decode($WIN32_OUTPUTCP,$_)} (wantarray() ? `$psCmd` : scalar(`$psCmd`));
  Win32::SetConsoleCP($previousCP);
  return @res;
};

my %options;
foreach my $arg (@ARGV) {
  if(substr($arg,0,2) eq '--') {
    my $cmdOpt=substr($arg,2);
    if(exists $cmdOpts{$cmdOpt}) {
      $options{$cmdOpt}++;
    }else{
      print "Option invalide \"$cmdOpt\"\n";
      usage();
    }
  }elsif(substr($arg,0,1) eq '-') {
    my $cmdOptsString=substr($arg,1);
    my @cmdOptsList=split(//,$cmdOptsString);
    foreach my $cmdOpt (@cmdOptsList) {
      if(exists $cmdOptsAliases{$cmdOpt}) {
        $options{$cmdOptsAliases{$cmdOpt}}++;
      }else{
        print "Option invalide \"$cmdOpt\"\n";
        usage();
      }
    }
  }else{
    print "Paramètre invalide \"$arg\"\n";
    usage();
  }
}
my $maxTransferDuration=8;
my $maxNbPings=10*2**($options{'extended-test'}//0);
$maxTransferDuration=15*2**($options{'extended-test'}-1) if($options{'extended-test'});

usage() if(any {$options{$_->[0]} && $options{$_->[1]}} (['check-update','skip-check-update'],
                                                         ['freebox','skip-freebox'],
                                                         ['freebox','upload'],
                                                         ['freebox','alternate-srv'],
                                                         ['freebox','all-srv'],
                                                         ['alternate-srv','all-srv'],
                                                         ['latency','skip-latency'],
                                                         ['latency','upload'],
                                                         ['net-conf','quiet'],
                                                         ['suggestions','quiet']));

quit("Le support d'IPv6 nécessite le module Perl IO::Socket::IP v0.25 ou supérieur") if($options{ipv6} && ! $IPV6_COMPAT);

sub usage {
  print "\nUsage:\n  $0 [<options>]\n";
  foreach my $cmdOpt (sort {my $cic=lc($cmdOpts{$a}[1]) cmp lc($cmdOpts{$b}[1]); $cic ? $cic : $cmdOpts{$b}[1] cmp $cmdOpts{$a}[1]} keys %cmdOpts) {
    print "      --$cmdOpt (-$cmdOpts{$cmdOpt}[1]) : $cmdOpts{$cmdOpt}[0]\n";
  }
  quit();
}

my $timestampPrinted;
sub quit {
  my $msg=shift;
  print "$msg\n" if(defined $msg);
  if($timestampPrinted) {
    printTimestampLine();
  }else{
    print "\n";
  }
  if(MSWIN32) {
    print "Appuyer sur Entrée pour quitter...\n";
    <STDIN>;
  }
  exit;
}

sub printTimestampLine {
  my $timestamp=time();
  my @localtime=localtime($timestamp);
  $localtime[4]++;
  @localtime = map {sprintf('%02d',$_)} @localtime;
  my $timeString=($localtime[5]+1900)
      .'-'.$localtime[4]
      .'-'.$localtime[3]
      .' '.$localtime[2]
      .':'.$localtime[1]
      .':'.$localtime[0]
      .' '.getTzOffset($timestamp);
  my $timestampPadding='-' x (int(77-length($timeString))/2);
  print "$timestampPadding $timeString $timestampPadding\n";
  $timestampPrinted=1;
}

sub getTzOffset {
  my $t=defined $_[0] ? $_[0] : time();
  my ($lMin,$lHour,$lYear,$lYday)=(localtime($t))[1,2,5,7];
  my ($gMin,$gHour,$gYear,$gYday)=(gmtime($t))[1,2,5,7];
  my $deltaMin=($lMin-$gMin)+($lHour-$gHour)*60+( $lYear-$gYear || $lYday - $gYday)*24*60;
  my $sign=$deltaMin>=0?'+':'-';
  $deltaMin=abs($deltaMin);
  my ($deltaHour,$deltaHourMin)=(int($deltaMin/60),$deltaMin%60);
  return $sign.sprintf('%.2u%.2u',$deltaHour,$deltaHourMin);
}

sub checkForNewVersion {
  return unless($VERSION =~ /^(\d+)\.(\d+)$/);
  my ($currentVersionMajor,$currentVersionMinor)=($1,$2);
  $httpClient->{timeout}=10;
  my $result=$httpClient->get('http://checkversion.royalwebhosting.net/'.lc($PROGRAM_NAME));
  if($result->{success}) {
    my $newVersion=$result->{content};
    if($newVersion =~ /^(\d+)\.(\d+)$/) {
      my ($latestVersionMajor,$latestVersionMinor)=($1,$2);
      $newVersion="$latestVersionMajor.$latestVersionMinor";
      if($latestVersionMajor > $currentVersionMajor
         || ($latestVersionMajor == $currentVersionMajor && $latestVersionMinor > $currentVersionMinor)) {
        print +('-' x 79)."\n";
        print "Une nouvelle version de $PROGRAM_NAME est disponible ($newVersion)\n";
        print "Vous utilisez actuellement la version $VERSION\n";
        print "Vous pouvez télécharger la dernière version à partir du lien ci-dessous:\n";
        print "  https://github.com/Yaribz/$PROGRAM_NAME/releases/latest/download/$PROGRAM_NAME.".($0 =~ /\.exe$/i ? 'exe' : 'pl')."\n";
        print "Vous pouvez désactiver la vérification de version avec le paramètre --skip-check-update (-C)\n";
        print +('-' x 79)."\n";
        print "Appuyer sur Ctrl-c pour quitter, ou Entrée pour continuer avec votre version actuelle.\n";
        exit unless(defined <STDIN>);
      }
    }else{
      print "[!] Impossible de vérifier si une nouvelle version est disponible (valeur de nouvelle version invalide \"$newVersion\")\n";
    }
  }else{
    my $errorDetail = $result->{status} == 599 ? $result->{content} : "HTTP status: $result->{status}, reason: $result->{reason}";
    $errorDetail=~s/\x{0092}/'/g if(MSWIN32);
    chomp($errorDetail);
    print "[!] Impossible de vérifier si une nouvelle version est disponible ($errorDetail)\n";
  }
}

sub printIntroMsg {
  print <<EOT;
===============================================================================
$PROGRAM_NAME
---------------
Programme de diagnostic de connexion FTTH Free

Ce programme analyse la configuration réseau du système et effectue différents
tests TCP (latence et débit mono-connexion) afin d'évaluer les performances de
la connexion FTTH et détecter d'éventuels dysfonctionnements.
Diverses options sont disponibles pour configurer ou désactiver certains tests,
voir --help (-h) pour plus d'information.

Avant de continuer, veuillez vérifier que rien d'autre ne consomme de la bande
passante sur le réseau (ordinateurs, Freebox player, télévision...), ni du CPU
sur le système de test (mises à jour automatiques, antivirus...).
===============================================================================
Appuyer sur Entrée pour continuer (ou Ctrl-C pour annuler)...
EOT
  exit unless(defined <STDIN>);
}

sub printHeaderLine {
  my $osName=getOsName()//$^O;
  my $cbofTag="[$PROGRAM_NAME v$VERSION]";
  my $osNamePaddingLength=79-length($cbofTag)-length($osName);
  $osNamePaddingLength=1 if($osNamePaddingLength < 1);
  print $cbofTag.(' ' x $osNamePaddingLength).$osName."\n";
}

sub getOsName {
  my $n;
  if(MSWIN32) {
    $n=Win32::GetOSDisplayName();
    substr($n,9,1)='1' if(substr($n,0,10) eq 'Windows 10' && (Win32::GetOSVersion())[3] >= 22000);
  }else{
    my @uname=POSIX::uname();
    my ($sysName,$sysRelease,$sysArch)=@uname[0,2,4];
    if($sysName) {
      $n=$sysName;
      $n.=" $sysRelease" if($sysRelease);
      $n.=" ($sysArch)" if($sysArch);
    }
  }
  return $n;
}

my %netConf;
my %WIN32_TCP_SETTINGS = map {$_ => 1} (qw'AutoTuningLevelEffective AutoTuningLevelGroupPolicy AutoTuningLevelLocal CongestionProvider EcnCapability ScalingHeuristics Timestamps');
my %netAdapterErrors;
sub getNetConf {
  if(MSWIN32) {
    my $TCP_PROPERTIES=join(', ',keys %WIN32_TCP_SETTINGS);
    my $NET_ADAPTER_ADVANCED_PROPERTIES=join(', ',(qw'EEE FlowControl InterruptModeration IPChecksumOffloadIPv4 JumboPacket LsoV1IPv4 LsoV2IPv4 LsoV2IPv6 LSOv2IPv4 LSOv2IPv6 PacketCoalescing ReceiveBuffers RscIPv4 RscIPv6 SpeedDuplex TCPChecksumOffloadIPv4 TCPChecksumOffloadIPv6 TCPConnectionOffloadIPv4 TCPConnectionOffloadIPv6 TCPUDPChecksumOffloadIPv4 TCPUDPChecksumOffloadIPv6 TransmitBuffers'));
    my $defaultIp = $options{ipv6} ? '::0' : '0.0.0.0';
    my $powershellScript = (<<"END_OF_POWERSHELL_SCRIPT" =~ s/\n//gr);
\$ErrorActionPreference='silentlycontinue';

Get-NetTCPSetting Internet | Format-List -Property $TCP_PROPERTIES;

\$defaultInterfaceName=(Find-NetRoute -RemoteIpAddress $defaultIp)[0].InterfaceAlias;

if(\$defaultInterfaceName -ne \$null) {

  Get-NetAdapter -Name \$defaultInterfaceName | Format-List -Property LinkSpeed, PhysicalMediaType, DriverDescription, DriverProvider, DriverVersionString, DriverDate;

  \$advancedProperties = New-Object PSObject;
  Get-NetAdapterAdvancedProperty -Name \$defaultInterfaceName | Where-Object -Property RegistryKeyword -Match '^\\*' | ForEach-Object { \$advancedProperties | Add-Member -MemberType NoteProperty -Name (\$_.RegistryKeyword).substring(1) -Value \$_.DisplayValue };
  \$advancedProperties | Format-List -Property $NET_ADAPTER_ADVANCED_PROPERTIES;

  Get-NetAdapterHardwareInfo -Name \$defaultInterfaceName | Format-List -Property PcieLinkSpeed, PcieLinkWidth;

  Get-NetConnectionProfile -InterfaceAlias \$defaultInterfaceName | Format-List -Property NetworkCategory;

  Get-NetAdapterStatistics -Name \$defaultInterfaceName | Format-List -Property OutboundDiscardedPackets, OutboundPacketErrors, ReceivedDiscardedPackets, ReceivedPacketErrors;

}
END_OF_POWERSHELL_SCRIPT
    my @netConfLines = win32PowershellExec($powershellScript);
    map {$netConf{$1}=$2 if(/^\s*([^:]*[^\s:])\s*:\s*(.*[^\s])\s*$/)} @netConfLines;
    foreach my $netAdapterCounter (qw'OutboundDiscardedPackets OutboundPacketErrors ReceivedDiscardedPackets ReceivedPacketErrors') {
      $netAdapterErrors{$netAdapterCounter} = delete $netConf{$netAdapterCounter} if(exists $netConf{$netAdapterCounter});
    }
    if(defined $netConf{AutoTuningLevelEffective}) {
      if($netConf{AutoTuningLevelEffective} eq 'Local') {
        delete $netConf{AutoTuningLevelGroupPolicy};
        delete $netConf{AutoTuningLevelEffective};
      }elsif($netConf{AutoTuningLevelEffective} eq 'GroupPolicy') {
        delete $netConf{AutoTuningLevelLocal};
        delete $netConf{AutoTuningLevelEffective};
      }
    }
    $netConf{Driver} = delete $netConf{DriverDescription}
      if(exists $netConf{DriverDescription});
    if(exists $netConf{DriverVersionString}) {
      $netConf{DriverVersion}=delete $netConf{DriverVersionString};
      my @driverVersionDetails;
      map {push(@driverVersionDetails,delete $netConf{$_}) if(exists $netConf{$_})} (qw'DriverProvider DriverDate');
      $netConf{DriverVersion}.=' ('.join(', ',@driverVersionDetails).')' if(@driverVersionDetails);
    }
    $netConf{JumboPacket}='Disabled'
        if(exists $netConf{JumboPacket} && $netConf{JumboPacket} eq '1514');
    my @ipVersionedParams;
    map  {push(@ipVersionedParams,$1) if(/^(.+)IPv4$/)} (keys %netConf);
    foreach my $ipVersionedParam (@ipVersionedParams) {
      my ($ipv4Param,$ipv6Param) = map {$ipVersionedParam.$_} (qw'IPv4 IPv6');
      if(exists $netConf{$ipv6Param} && $netConf{$ipv4Param} eq $netConf{$ipv6Param}) {
        $netConf{$ipVersionedParam} = delete $netConf{$ipv4Param};
        delete $netConf{$ipv6Param};
      }
    }
  }elsif(my $sysctlBin=findSysctlBin()) {
    my @netConfFields;
    if(LINUX) {
      @netConfFields=qw'
          net.core.default_qdisc
          net.core.netdev_budget
          net.core.netdev_max_backlog
          net.core.rmem_max
          net.core.wmem_max
          net.ipv4.tcp_adv_win_scale
          net.ipv4.tcp_congestion_control
          net.ipv4.tcp_dsack
          net.ipv4.tcp_ecn
          net.ipv4.tcp_mem
          net.ipv4.tcp_no_metrics_save
          net.ipv4.tcp_rmem
          net.ipv4.tcp_sack
          net.ipv4.tcp_timestamps
          net.ipv4.tcp_window_scaling
          net.ipv4.tcp_wmem';
    }else{
      @netConfFields=qw'
          kern.ipc.maxsockbuf
          net.inet.ip.ifq.maxlen
          net.inet.ip.intr_queue_maxlen
          net.inet.ip.maxqueue
          net.inet.tcp.sendspace
          net.inet.tcp.recvspace
          net.inet.tcp.sendbuf_auto
          net.inet.tcp.doautosndbuf
          net.inet.tcp.sendbuf_max
          net.inet.tcp.autosndbufmax
          net.inet.tcp.sendbuf_inc
          net.inet.tcp.sendbuf_auto_lowat
          net.inet.tcp.recvbuf_auto
          net.inet.tcp.doautorcvbuf
          net.inet.tcp.recvbuf_max
          net.inet.tcp.autorcvbufmax
          net.inet.tcp.recvbuf_inc
          net.inet.tcp.reass.maxqueuelen
          net.inet.tcp.sack.enable
          net.inet.tcp.ecn.enable
          net.inet.tcp.hostcache.enable
          net.inet.tcp.rfc1323
          net.inet.tcp.rfc3042
          net.inet.tcp.functions_available
          net.inet.tcp.functions_default
          net.inet.tcp.cc.available
          net.inet.tcp.cc.algorithm
          net.inet.tcp.timestamps
          net.inet.tcp.congctl.available
          net.inet.tcp.congctl.selected
          net.inet.tcp.reasslimit
          net.inet.tcp.sack
          net.inet.tcp.ecn
          net.inet6.ip6.ifq.maxlen
          net.inet6.ip6.intr_queue_maxlen
          net.link.generic.system.rcvq_maxlen
          net.link.generic.system.sndq_maxlen
          net.link.ifqmaxlen';
    }
    my @netConfLines=`$sysctlBin -a 2>/dev/null`;
    foreach my $line (@netConfLines) {
      if($line =~ /^\s*([^:=]*[^\s:=])\s*[:=]\s*(.*[^\s])\s*$/ && (any {$1 eq $_} @netConfFields)) {
        $netConf{$1}=$2;
      }
    }
  }
}

sub findSysctlBin {
  my $sysctlBin;
  foreach my $knownPath (qw'/sbin/sysctl /usr/sbin/sysctl') {
    if(-x $knownPath) {
      $sysctlBin=$knownPath;
      last;
    }
  }
  if(! defined $sysctlBin) {
    require IPC::Cmd;
    $sysctlBin=IPC::Cmd::can_run('sysctl');
  }
  return $sysctlBin;
}

my ($rcvWindow,$rmemMaxParam,$rmemMaxValuePrefix,$tcpAdvWinScale,$sndWindow,$wmemMaxParam,$wmemMaxValuePrefix,$degradedTcpConf);
sub netConfAnalysis {
  if(! %netConf) {
    print "[!] Echec de lecture de la configuration réseau du système\n";
    return;
  }
  print "Configuration réseau du système:\n";
  if(MSWIN32) {
    my %prefixedConf;
    foreach my $param (keys %netConf) {
      my $prefix;
      if($param eq 'NetworkCategory') {
        $prefix='NetProfile';
      }elsif(exists $WIN32_TCP_SETTINGS{$param}) {
        $prefix='Tcp';
      }else{
        $prefix='Adapter';
      }
      $prefixedConf{$prefix.'.'.$param}=$netConf{$param};
    }
    map {print "  $_: $prefixedConf{$_}\n"} (sort keys %prefixedConf);
    if(defined $netConf{AutoTuningLevelLocal}) {
      processWindowsAutoTuningLevel('AutoTuningLevelLocal');
      if($netConf{AutoTuningLevelLocal} ne 'Normal') {
        print "[!] La valeur actuelle de AutoTuningLevelLocal peut dégrader les performances\n";
        if($options{suggestions}) {
          print "    Recommandation: ajuster le paramètre avec l'une des deux commandes suivantes\n";
          print "      [PowerShell] Set-NetTCPSetting -SettingName Internet -AutoTuningLevelLocal Normal\n";
          print "      [cmd.exe] netsh interface tcp set global autotuninglevel=normal\n";
        }
      }
    }elsif(defined $netConf{AutoTuningLevelGroupPolicy}) {
      processWindowsAutoTuningLevel('AutoTuningLevelGroupPolicy');
      if($netConf{AutoTuningLevelGroupPolicy} ne 'Normal') {
        print "[!] La stratégie de groupe appliquée aux paramètres AutoTuningLevelEffective et AutoTuningLevelGroupPolicy peut dégrader les performances\n";
        if($options{suggestions}) {
          print "    Recommandation: effectuer l'une des deux actions suivantes\n";
          print "      - configurer la valeur du paramètre AutoTuningLevelGroupPolicy à \"Normal\" dans la stratégie de groupe\n";
          print "      - utiliser la configuration locale pour ce paramètre (configurer le valeur du paramètre AutoTuningLevelEffective à \"Local\")\n";
        }
      }
    }
    if(defined $netConf{ScalingHeuristics} && $netConf{ScalingHeuristics} ne 'Disabled') {
      $degradedTcpConf=1;
      print "[!] La valeur actuelle de ScalingHeuristics peut dégrader les performances\n";
      if($options{suggestions}) {
        print "    Recommandation: ajuster le paramètre avec une des deux commandes suivantes\n";
        print "      [PowerShell] Set-NetTCPSetting -SettingName Internet -ScalingHeuristics Disabled\n";
        print "      [cmd.exe] netsh interface tcp set heuristics disabled\n";
      }
    }
    if(defined $netConf{LinkSpeed} && $netConf{LinkSpeed} ne 'Unknown'
       && defined $netConf{PcieLinkSpeed} && $netConf{PcieLinkSpeed} ne 'Unknown'
       && defined $netConf{PcieLinkWidth}) {
      if($netConf{LinkSpeed} =~ /^(\d+) ([KMGT]?)bps$/) {
        my ($linkSpeed,$unitPrefix)=($1,$2);
        $linkSpeed*={K => 1E3, M => 1E6, G => 1E9, T => 1E12}->{$unitPrefix} if($unitPrefix);
        if($netConf{PcieLinkSpeed} =~ /^(\d+(?:\.\d)?) GT\/s$/) {
          my $pcieEfficiency;
          if($1 < 8) {
            $pcieEfficiency=4/5;
          }elsif($1 < 64) {
            $pcieEfficiency=64/65;
          }else{
            $pcieEfficiency=121/128;
          }
          my $pcieLinkSpeed = $1 * 1E9 * $pcieEfficiency;
          if($netConf{PcieLinkWidth} =~ /^\d+$/) {
            $pcieLinkSpeed*=$netConf{PcieLinkWidth};
            if($pcieLinkSpeed < $linkSpeed) {
              print "[!] La carte réseau utilise actuellement une interface PCI Express avec un taux de transfert ne permettant pas d'atteindre le débit maximum du lien réseau\n";
              print "    Recommandation: connecter la carte réseau sur un autre slot PCI Express (consulter le manuel de la carte mère si besoin pour trouver un slot adéquat)\n"
                  if($options{suggestions});
            }
          }else{
            print "[!] Valeur de PcieLinkWidth non reconnue\n";
          }
        }else{
          print "[!] Valeur de PcieLinkSpeed non reconnue\n";
        }
      }else{
        print "[!] Valeur de LinkSpeed non reconnue\n";
      }
    }
  }else{
    map {print "  $_: $netConf{$_}\n"} (sort keys %netConf);
    if(LINUX) {
      my $rmemMax;
      if(defined $netConf{'net.core.rmem_max'}) {
        if($netConf{'net.core.rmem_max'} =~ /^\s*(\d+)\s*$/) {
          ($rmemMax,$rmemMaxParam)=($1,'net.core.rmem_max');
        }else{
          print "[!] Valeur de net.core.rmem_max non reconnue\n";
        }
      }
      if(defined $netConf{'net.ipv4.tcp_rmem'}) {
        if($netConf{'net.ipv4.tcp_rmem'} =~ /^\s*(\d+)\s+(\d+)\s+(\d+)\s*$/) {
          ($rmemMax,$rmemMaxParam,$rmemMaxValuePrefix)=($3,'net.ipv4.tcp_rmem',"$1 $2 ");
        }else{
          print "[!] Valeur de net.ipv4.tcp_rmem non reconnue\n";
        }
      }
      if(defined $netConf{'net.ipv4.tcp_adv_win_scale'}) {
        if($netConf{'net.ipv4.tcp_adv_win_scale'} =~ /^\s*(-?\d+)\s*$/ && $&) {
          $tcpAdvWinScale=$1;
        }else{
          print "[!] Valeur de net.ipv4.tcp_adv_win_scale non reconnue\n";
        }
      }
      if(defined $rmemMax) {
        if(defined $tcpAdvWinScale) {
          my $overHeadFactor=2 ** abs($tcpAdvWinScale);
          $rcvWindow=$rmemMax/$overHeadFactor;
          $rcvWindow=$rmemMax-$rcvWindow if($tcpAdvWinScale > 0);
        }else{
          print "[!] Valeur de net.ipv4.tcp_adv_win_scale non trouvée\n";
        }
      }
      my $wmemMax;
      if(defined $netConf{'net.core.wmem_max'}) {
        if($netConf{'net.core.wmem_max'} =~ /^\s*(\d+)\s*$/) {
          ($wmemMax,$wmemMaxParam)=($1,'net.core.wmem_max');
        }else{
          print "[!] Valeur de net.core.wmem_max non reconnue\n";
        }
      }
      if(defined $netConf{'net.ipv4.tcp_wmem'}) {
        if($netConf{'net.ipv4.tcp_wmem'} =~ /^\s*(\d+)\s+(\d+)\s+(\d+)\s*$/) {
          ($wmemMax,$wmemMaxParam,$wmemMaxValuePrefix)=($3,'net.ipv4.tcp_wmem',"$1 $2 ");
        }else{
          print "[!] Valeur de net.ipv4.tcp_wmem non reconnue\n";
        }
      }
      $sndWindow=$wmemMax*$TCP_WMEM_SND_WINDOW_RATIO if(defined $wmemMax);
    }else{
      my %bsdParams;
      if(defined $netConf{'kern.ipc.maxsockbuf'}) {
        if($netConf{'kern.ipc.maxsockbuf'} =~ /^\s*(\d+)\s*$/) {
          $bsdParams{maxsockbuf}=$1;
        }else{
          print "[!] Valeur de kern.ipc.maxsockbuf non reconnue\n";
        }
      }
      foreach my $tcpParam (qw'recvbuf_auto doautorcvbuf sendbuf_auto doautosndbuf') {
        my $fullParam='net.inet.tcp.'.$tcpParam;
        if(defined $netConf{$fullParam}) {
          if($netConf{$fullParam} =~ /^\s*([01])\s*$/) {
            $bsdParams{$tcpParam}=$1;
          }else{
            print "[!] Valeur de $fullParam non reconnue\n";
          }
        }
      }
      foreach my $tcpParam (qw'recvbuf_max autorcvbufmax recvspace sendbuf_max autosndbufmax sendspace') {
        my $fullParam='net.inet.tcp.'.$tcpParam;
        if(defined $netConf{$fullParam}) {
          if($netConf{$fullParam} =~ /^\s*(\d+)\s*$/) {
            $bsdParams{$tcpParam}=$1;
          }else{
            print "[!] Valeur de $fullParam non reconnue\n";
          }
        }
      }
      if(defined $bsdParams{maxsockbuf} && defined $bsdParams{recvspace} && defined $bsdParams{sendspace} && $bsdParams{maxsockbuf} < $bsdParams{recvspace} + $bsdParams{sendspace}) {
        $bsdParams{maxsockbuf}=$bsdParams{recvspace}+$bsdParams{sendspace};
      }
      my $recvBufMaxParam = defined $bsdParams{recvbuf_max} ? 'recvbuf_max' : defined $bsdParams{autorcvbufmax} ? 'autorcvbufmax' : undef;
      my $sendBufMaxParam = defined $bsdParams{sendbuf_max} ? 'sendbuf_max' : defined $bsdParams{autosndbufmax} ? 'autosndbufmax' : undef;
      my $recvBufAutoEnabled=$bsdParams{recvbuf_auto}//$bsdParams{doautorcvbuf};
      $recvBufAutoEnabled//=1 if(defined $recvBufMaxParam);
      my $sendBufAutoEnabled=$bsdParams{sendbuf_auto}//$bsdParams{doautosndbuf};
      $sendBufAutoEnabled//=1 if(defined $sendBufMaxParam);
      if($recvBufAutoEnabled) {
        ($rmemMaxParam,$rcvWindow)=('kern.ipc.maxsockbuf',$bsdParams{maxsockbuf}-($bsdParams{sendspace}//0)) if(defined $bsdParams{maxsockbuf});
        ($rmemMaxParam,$rcvWindow)=('net.inet.tcp.'.$recvBufMaxParam,$bsdParams{$recvBufMaxParam}) if(defined $recvBufMaxParam && (! defined $rcvWindow || $rcvWindow > $bsdParams{$recvBufMaxParam}));
      }else{
        ($rmemMaxParam,$rcvWindow)=('net.inet.tcp.recvspace',$bsdParams{recvspace}) if(defined $bsdParams{recvspace});
      }
      if($sendBufAutoEnabled) {
        ($wmemMaxParam,$sndWindow)=('kern.ipc.maxsockbuf',$bsdParams{maxsockbuf}) if(defined $bsdParams{maxsockbuf});
        ($wmemMaxParam,$sndWindow)=('net.inet.tcp.'.$sendBufMaxParam,$bsdParams{$sendBufMaxParam}) if(defined $sendBufMaxParam && (! defined $sndWindow || $sndWindow > $bsdParams{$sendBufMaxParam}));
      }else{
        ($wmemMaxParam,$sndWindow)=('net.inet.tcp.sendspace',$bsdParams{sendspace}) if(defined $bsdParams{sendspace});
      }
    }
  }
  if(defined $rcvWindow) {
    my $maxRttMsFor1Gbps = int($rcvWindow * 1000 / $GOODPUT_1Gbps_Bytes + 0.5);
    print "  => Latence TCP max pour une réception à 1 Gbps: ${maxRttMsFor1Gbps} ms\n";
    if(! MSWIN32 && $maxRttMsFor1Gbps < $RECOMMENDED_MIN_RTT_MAX_FOR_FULL_BANDWIDTH) {
      if(LINUX) {
        if($tcpAdvWinScale < -3) {
          print "[!] Les valeurs actuelles de net.ipv4.tcp_adv_win_scale et $rmemMaxParam peuvent dégrader les performances\n";
        }else{
          print "[!] La valeur actuelle de $rmemMaxParam peut dégrader les performances\n";
          if($options{suggestions}) {
            print "    Recommandation: ajuster le paramètre avec la commande suivante\n";
            print "      sysctl -w $rmemMaxParam=".rcvWindowToRmemValue($RECOMMENDED_MIN_RCV_WINDOW_SIZE)."\n";
          }
        }
      }else{
        print "[!] La valeur actuelle de $rmemMaxParam peut dégrader les performances\n";
      }
    }
  }
  if(defined $sndWindow) {
    my $maxRttMsFor700Mbps = int($sndWindow * 1000 / $GOODPUT_700Mbps_Bytes + 0.5);
    print "  => Latence TCP max pour une émission à 700 Mbps: ${maxRttMsFor700Mbps} ms\n";
    if($maxRttMsFor700Mbps < $RECOMMENDED_MIN_RTT_MAX_FOR_FULL_BANDWIDTH) {
      print "[!] La valeur actuelle de $wmemMaxParam peut dégrader les performances\n";
      if(LINUX && $options{suggestions}) {
        print "    Recommandation: ajuster le paramètre avec la commande suivante\n";
        print "      sysctl -w $wmemMaxParam=".sndWindowToWmemValue($RECOMMENDED_MIN_SND_WINDOW_SIZE)."\n";
      }
    }
  }
}

my %windowsAutoTuningLevels=(Disabled => 0,
                             HighlyRestricted => 2,
                             Restricted => 4,
                             Normal => 8,
                             Experimental => 14);
sub processWindowsAutoTuningLevel {
  my $autoTuningParam=shift;
  my $autoTuningLevel=$netConf{$autoTuningParam};
  if(exists $windowsAutoTuningLevels{$autoTuningLevel}) {
    $rcvWindow=65535*2**$windowsAutoTuningLevels{$autoTuningLevel};
  }else{
    print "[!] Valeur de $autoTuningParam non reconnue\n";
    $degradedTcpConf=1;
  }
}

sub rcvWindowToRmemValue {
  my $newRcvWindow=shift;
  my $overHeadFactor=2 ** abs($tcpAdvWinScale);
  my $newRmemValue=$overHeadFactor*$newRcvWindow;
  $newRmemValue/=($overHeadFactor-1) if($tcpAdvWinScale > 0);
  $newRmemValue=fixMemSize($newRmemValue);
  $newRmemValue="\"$rmemMaxValuePrefix$newRmemValue\"" if(defined $rmemMaxValuePrefix);
  return $newRmemValue;
}

sub sndWindowToWmemValue {
  my $newSndWindow=shift;
  my $newWmemValue=(1/$TCP_WMEM_SND_WINDOW_RATIO)*$newSndWindow;
  $newWmemValue=fixMemSize($newWmemValue);
  $newWmemValue="\"$wmemMaxValuePrefix$newWmemValue\"" if(defined $wmemMaxValuePrefix);
  return $newWmemValue;
}

sub fixMemSize { return POSIX::ceil($_[0]/POSIX::BUFSIZ())*POSIX::BUFSIZ() }

sub checkNetAdapterErrors {
  return unless(MSWIN32 && %netAdapterErrors);
  my $defaultIp = $options{ipv6} ? '::0' : '0.0.0.0';
  my $powershellScript = (<<"END_OF_POWERSHELL_SCRIPT" =~ s/\n//gr);
\$ErrorActionPreference='silentlycontinue';
Get-NetAdapterStatistics -Name (Find-NetRoute -RemoteIpAddress $defaultIp)[0].InterfaceAlias | Format-List -Property OutboundDiscardedPackets, OutboundPacketErrors, ReceivedDiscardedPackets, ReceivedPacketErrors;
END_OF_POWERSHELL_SCRIPT
  my @statLines = win32PowershellExec($powershellScript);
  my %newErrorCounters;
  map {$newErrorCounters{$1}=$2 if(/^\s*([^:]*[^\s:])\s*:\s*(.*[^\s])\s*$/)} @statLines;
  foreach my $errorCounter (sort keys %newErrorCounters) {
    next unless(exists $netAdapterErrors{$errorCounter} && $newErrorCounters{$errorCounter} > $netAdapterErrors{$errorCounter});
    print "[!] Le compteur \"$errorCounter\" de l'interface réseau a été incrémenté de ".($newErrorCounters{$errorCounter}-$netAdapterErrors{$errorCounter})." pendant le test.\n";
    if($options{suggestions}) {
      print "    Recommandations:\n";
      if(substr($errorCounter,8) eq 'DiscardedPackets') {
        print '      - augmenter la taille de la mémoire tampon '.(substr($errorCounter,0,8) eq 'Received' ? 'de réception' : "d'envoi")." de l'interface réseau\n";
        print "      - vérifier qu'il n'existe pas un pilote plus récent ou plus adapté pour la carte réseau\n";
      }else{
        print "      - vérifier qu'il n'existe pas un pilote plus récent ou plus adapté pour la carte réseau\n";
        print "      - s'assurer du bon fonctionnement du matériel utilisé en le remplaçant ou en l'essayant sur un autre système (câbles réseau, modules optiques, carte réseau, mémoire vive...)\n";
        print "      - vérifier que les paramètres réseau du système sont cohérents avec le reste de l'infrastructure (mode de gestion d'énergie de la carte réseau, mode speed/duplex, MTU...)\n";
      }
    }
  }
  %netAdapterErrors=%newErrorCounters;
}

sub testTcp {
  my ($type,$ipv,$mode,$as,$cca)=@_;
  
  my ($testDescription,$testIp,$testPort,$testUrl,$testTimeout,$expectedMaxLatency)=getTestData(@_);
  print "Test TCP $testDescription\n";

  my ($r_checkMaxThroughputForLatency,$r_getSpeed);
  if($type eq 'local' || $mode eq 'download') {
    ($r_checkMaxThroughputForLatency,$r_getSpeed)=(\&checkMaxRcvThroughputForLatency,\&getDlSpeed);
  }else{
    ($r_checkMaxThroughputForLatency,$r_getSpeed)=(\&checkMaxSndThroughputForLatency,\&getUlSpeed);
  }
  
  my ($speed,$maxThroughput);

  if(! $options{'skip-latency'}) {
    my ($rttMs,$jitter)=getTcpLatency($testIp,$testPort,$ipv,$testTimeout,$maxNbPings);
    if(! defined $rttMs) {
      if($type eq 'local') {
        print "[!] Echec du test de latence\n";
        print "    En cas d'absence de Freebox, le paramètre --skip-freebox (-F) peut être utilisé pour désactiver le test local\n";
        return undef;
      }else{
        quit('[!] Echec du test de latence');
      }
    }
    print "  --> Latence: $rttMs ms\t\t\t[gigue: $jitter ms]\n";
    print '[!] Latence élevée pour une connexion '.($type eq 'local' ? 'locale' : 'FTTH')."\n" if($rttMs > $expectedMaxLatency);
    $maxThroughput=$r_checkMaxThroughputForLatency->($rttMs);
  }
  
  if(! $options{latency}) {
    $httpClient->{timeout}=$testTimeout;
    my $r_chunksData;
    ($speed,$r_chunksData)=$r_getSpeed->($testUrl);
    if(! defined $speed) {
      if($type eq 'local' && $options{'skip-latency'}) {
        print "[!] Echec du test de débit\n";
        print "    En cas d'absence de Freebox, le paramètre --skip-freebox (-F) peut être utilisé pour désactiver le test local\n";
        return undef;
      }else{
        quit('[!] Echec du test de débit');
      }
    }
    my ($totalChunksTime,$totalChunksDataSize);
    map {$totalChunksTime+=$_->[0];$totalChunksDataSize+=$_->[1]} @{$r_chunksData};
    my $chunksAvgSpeed=$totalChunksDataSize/$totalChunksTime;
    my $chunksSquaredDeviations;
    map {$chunksSquaredDeviations+=($_->[1]/$_->[0]-$chunksAvgSpeed)**2*$_->[0]} @{$r_chunksData};
    my $dlSpeedRSD=sprintf('%.2f',sqrt($chunksSquaredDeviations/$totalChunksTime)*100/$chunksAvgSpeed);
    print "  --> Débit: ".readableSpeed($speed)."\t[fluctuation: ${dlSpeedRSD}%]\n";
  }
  
  checkNetAdapterErrors() unless($options{quiet});
  
  return ($speed,$maxThroughput);
}

sub getTestData {
  my ($type,$ipv,$mode,$as,$cca)=@_;
  my $testDescription="$type ($ipv): ";
  if($type eq 'local') {
    $testDescription.=($options{latency}?'':'téléchargement depuis la ').'Freebox';
  }else{
    $testDescription .= $mode eq 'download' ? "téléchargement depuis l'" : "envoi vers l'" if(! $options{latency});
    $testDescription.="AS $as ($AS_NAMES{$as}) ";
    if($mode eq 'download') {
      $testDescription.="[$cca]";
    }else{
      my $uploadCca=uc($netConf{CongestionProvider}//$netConf{'net.ipv4.tcp_congestion_control'}//'?');
      $testDescription.="[$uploadCca]";
    }
  }
  my $r_testData=\%TEST_DATA;
  while(my $testMode=shift) {
    $r_testData=$r_testData->{$testMode};
  }
  return ($testDescription,@{$r_testData}[0,1],"http://$r_testData->[0]:$r_testData->[1]$r_testData->[2]",@{$r_testData}[3,4]);
}

my %latencyCache;
sub getTcpLatency {
  my ($ip,$port,$ipv,$timeout,$nbPings)=@_;
  $port//=80;
  $timeout//=5;
  $nbPings//=10;

  my ($nbFailures,$maxFailures)=(0,2);
  
  return wantarray() ? @{$latencyCache{"$ip:$port"}} : $latencyCache{"$ip:$port"}->[0] if(defined $latencyCache{"$ip:$port"});

  # use parameter list form of Net::Ping constructor call to workaround bug https://rt.cpan.org/Public/Bug/Display.html?id=131919
  my $streamPinger=Net::Ping->new('stream',$timeout,undef,undef,undef,undef,lc($ipv)); 
  $streamPinger->hires();
  $streamPinger->port_number($port);
  my @pingTimes;
  for my $i (1..$nbPings) {
    my $elapsedTime=time();
    if(! $streamPinger->open($ip)) {
      $streamPinger->close();
      $nbFailures++;
      return undef if($nbFailures >= $maxFailures);
      next;
    }
    my ($pingRes,$pingTime)=$streamPinger->ping($ip);
    $streamPinger->close();
    if(! defined $pingRes || ! defined $pingTime) {
      $nbFailures++;
      return undef if($nbFailures >= $maxFailures);
      next;
    }
    push(@pingTimes,$pingTime);
    $elapsedTime=time()-$elapsedTime;
    sleep(0.5-$elapsedTime) if($elapsedTime < 0.5 && $i < $nbPings);
  }

  my $avgPing=sum0(@pingTimes)/@pingTimes;
  my $jitter=sum0(map {abs($_-$avgPing)} @pingTimes)/@pingTimes;
  my $medianPing=getMedianValue(\@pingTimes);
  $latencyCache{"$ip:$port"}=[map {sprintf('%.2f',$_*1000)} (min($avgPing,$medianPing),$jitter)];
  return wantarray() ? @{$latencyCache{"$ip:$port"}} : $latencyCache{"$ip:$port"}->[0];
}

sub getMedianValue {
  my $r_a=shift;
  return undef unless(@{$r_a});
  my @s=sort {$a <=> $b} @{$r_a};
  my $mid=@s/2;
  return ($s[int($mid-0.5)]+$s[int($mid)])/2;
}

sub checkMaxRcvThroughputForLatency {
  return undef unless($rcvWindow && ! $options{quiet});
  my $latency=shift;
  my $maxThroughput=$rcvWindow*1000/$latency;
  if($maxThroughput < $GOODPUT_1Gbps_Bytes) {
    print "[!] Avec cette latence, le paramétrage actuel de mémoire tampon TCP pourrait limiter le débit en réception à environ ".readableSpeed($maxThroughput)."\n";
    if(LINUX && $options{suggestions} && $tcpAdvWinScale > -4) {
      print "    Recommandation: si la latence estimée est correcte, augmenter la mémoire tampon max avec la commande suivante\n";
      print "      sysctl -w $rmemMaxParam=".rcvWindowToRmemValue($GOODPUT_1Gbps_Bytes*$latency/1000)."\n";
    }
    return $maxThroughput;
  }
  return undef;
}

sub checkMaxSndThroughputForLatency {
  return undef unless($sndWindow && ! $options{quiet});
  my $latency=shift;
  my $maxThroughput=$sndWindow*1000/$latency;
  if($maxThroughput < $GOODPUT_700Mbps_Bytes) {
    print "[!] Avec cette latence, le paramétrage actuel de mémoire tampon TCP pourrait limiter le débit en émission à environ ".readableSpeed($maxThroughput)."\n";
    if(LINUX && $options{suggestions}) {
      print "    Recommandation: si la latence estimée est correcte, augmenter la mémoire tampon max avec la commande suivante\n";
      print "      sysctl -w $wmemMaxParam=".sndWindowToWmemValue($GOODPUT_700Mbps_Bytes*$latency/1000)."\n";
    }
    return $maxThroughput;
  }
  return undef;
}

sub getDlSpeed {
  my ($url,$slowStartSkipDelay)=@_;
  $slowStartSkipDelay//=2;
  
  my ($startTime,$downloadedSize,$dlSpeed);
  my ($chunkStartTime,$chunkEndTime,$chunkDownloadedSize,@chunkDlData);
  my ($realStartTime,$r_dataCallback);
  if(wantarray()) {
    $r_dataCallback = sub {
      my $currentTime=time();
      if(! defined $startTime) {
        return if($currentTime-$realStartTime<$slowStartSkipDelay);
        $startTime=$currentTime;
        ($chunkStartTime,$chunkEndTime)=($startTime,$startTime+1);
        return;
      }
      my $dlSize=length($_[0]);
      $downloadedSize+=$dlSize;
      $chunkDownloadedSize+=$dlSize;
      if($currentTime > $chunkEndTime) {
        push(@chunkDlData,[$currentTime-$chunkStartTime,$chunkDownloadedSize]);
        $chunkStartTime=$currentTime;
        do { $chunkEndTime++ } while($chunkEndTime < $chunkStartTime+0.5);
        $chunkDownloadedSize=0;
      }
      if($currentTime-$realStartTime>$maxTransferDuration) {
        $dlSpeed=$downloadedSize/($currentTime-$startTime);
        die 'MAX_DL_DURATION';
      }
    };
  }else{
    $r_dataCallback = sub {
      my $currentTime=time();
      if(! defined $startTime) {
        return if($currentTime-$realStartTime<$slowStartSkipDelay);
        $startTime=$currentTime;
        return;
      }
      $downloadedSize+=length($_[0]);
      if($currentTime-$realStartTime>$maxTransferDuration) {
        $dlSpeed=$downloadedSize/($currentTime-$startTime);
        die 'MAX_DL_DURATION';
      }
    };
  }
  $realStartTime=time();
  if($slowStartSkipDelay == 0) {
    $startTime=$realStartTime;
    ($chunkStartTime,$chunkEndTime)=($startTime,$startTime+1);
  }
  my $result=$httpClient->get($url,{data_callback => $r_dataCallback});
  my $endTime=time();
  if($result->{success}) {
    quit("[!] Impossible d'évaluer le débit nominal (téléchargement trop court pour supprimer la phase de \"slow-start\")") unless($downloadedSize && $endTime > $startTime+$slowStartSkipDelay+1);
    $dlSpeed=$downloadedSize/($endTime-$startTime) ;
  }
  if($result->{success} || ($result->{status} == 599 && substr($result->{content},0,15) eq 'MAX_DL_DURATION')) {
    if(wantarray()) {
      if(! @chunkDlData) {
        print "[!] Echec de téléchargement de \"$url\" (timeout)\n";
        return undef;
      }
      return ($dlSpeed,\@chunkDlData);
    }
    return $dlSpeed;
  }else{
    my $errorDetail = $result->{status} == 599 ? $result->{content} : "HTTP status: $result->{status}, reason: $result->{reason}";
    $errorDetail=~s/\x{0092}/'/g if(MSWIN32);
    chomp($errorDetail);
    print "[!] Echec de téléchargement de \"$url\" ($errorDetail)\n";
    return undef;
  }
}

sub getUlSpeed {
  my ($url,$slowStartSkipDelay)=@_;
  $slowStartSkipDelay//=2;
  
  my ($minUlBufferSizeIdx,$maxUlBufferSizeIdx)=(16,25);
  my $ulBufferSize=2**$maxUlBufferSizeIdx;
  
  my $ulBufferData="$PROGRAM_NAME v$VERSION. ";
  $ulBufferData=($ulBufferData x int($ulBufferSize/length($ulBufferData))).substr($ulBufferData,0,$ulBufferSize % length($ulBufferData));
  die unless(length($ulBufferData) == $ulBufferSize);

  my $ulBufferSizeIdx=$minUlBufferSizeIdx;
  $ulBufferSize=2**$ulBufferSizeIdx;

  my $realStartTime=time();
  my ($lastBufferSizeAdjTime,$lastCbTime)=($realStartTime,$realStartTime);
  
  my ($startTime,$endTime,$uploadedSize);
  my ($chunkStartTime,$chunkEndTime,$chunkUploadedSize,@chunkUlData);

  if($slowStartSkipDelay == 0) {
    $startTime=$realStartTime;
    ($chunkStartTime,$chunkEndTime)=($startTime,$startTime+1);
  }
  
  my $chunkMode=wantarray();
  
  my $r_dataCallback = sub {
    my $currentTime=time();
    my $totalElapsedTime=$currentTime-$realStartTime;
    if($totalElapsedTime>0.4 && $currentTime-$lastBufferSizeAdjTime>0.1) {
      if($currentTime-$lastCbTime < 0.25 && $ulBufferSizeIdx<$maxUlBufferSizeIdx) {
        $ulBufferSizeIdx++;
        $ulBufferSize*=2;
        $lastBufferSizeAdjTime=$currentTime;
      }elsif($currentTime-$lastCbTime > 0.75 && $ulBufferSizeIdx>$minUlBufferSizeIdx) {
        $ulBufferSizeIdx--;
        $ulBufferSize/=2;
        $lastBufferSizeAdjTime=$currentTime;
      }
    }
    $lastCbTime=$currentTime;
    if(! defined $startTime) {
      return substr($ulBufferData,0,$ulBufferSize) if($totalElapsedTime<$slowStartSkipDelay);
      $startTime=$currentTime;
      ($chunkStartTime,$chunkEndTime)=($startTime,$startTime+1) if($chunkMode);
    }
    if($chunkMode && $currentTime > $chunkEndTime) {
      push(@chunkUlData,[$currentTime-$chunkStartTime,$chunkUploadedSize]);
      $chunkStartTime=$currentTime;
      do { $chunkEndTime++ } while($chunkEndTime < $chunkStartTime+0.5);
      $chunkUploadedSize=0;
    }
    if($totalElapsedTime>$maxTransferDuration) {
      $endTime=time();
      return '';
    }
    $chunkUploadedSize+=$ulBufferSize if($chunkMode);
    $uploadedSize+=$ulBufferSize;
    return substr($ulBufferData,0,$ulBufferSize);
  };
  
  my $result=$httpClient->post($url,{content => $r_dataCallback,
                                     headers => {'content-type' => 'application/octet-stream'}});
  $endTime//=time();
  if($result->{success}) {
    quit("[!] Impossible d'évaluer le débit nominal (téléchargement trop court pour supprimer la phase de \"slow-start\")") unless($uploadedSize && $endTime > $startTime+$slowStartSkipDelay+1);
    my $ulSpeed=$uploadedSize/($endTime-$startTime);
    return wantarray() ? ($ulSpeed,\@chunkUlData) : $ulSpeed;
  }else{
    my $errorDetail = $result->{status} == 599 ? $result->{content} : "HTTP status: $result->{status}, reason: $result->{reason}";
    $errorDetail=~s/\x{0092}/'/g if(MSWIN32);
    chomp($errorDetail);
    quit("[!] Echec d'envoi vers \"$url\" ($errorDetail)");
  }
}

sub readableSpeed {
  my $speed=shift;
  my $bitSpeed=$speed*8;
  my @units=('',qw'K M G T');
  my $unitIdx=0;
  my $unitFactor = $options{'binary-units'} ? 1024 : 1000;
  while($speed >= $unitFactor) {
    $speed/=$unitFactor;
    $unitIdx++;
  }
  my $bitUnitIdx=0;
  while($bitSpeed >= $unitFactor) {
    $bitSpeed/=$unitFactor;
    $bitUnitIdx++;
  }
  return sprintf('%.2f',$speed).' '.$units[$unitIdx].($options{'binary-units'} ? 'i' : '').'o/s ('.sprintf('%.2f',$bitSpeed).' '.$units[$bitUnitIdx].($options{'binary-units'} ? 'i' : '').'bps)';
}

my $crNeeded;
sub printDiag {
  print "\n" if($crNeeded);
  print shift."\n";
  $crNeeded=0;
}

usage() if($options{help});
quit("$PROGRAM_NAME v$VERSION") if($options{version});
checkForNewVersion() unless($options{'skip-check-update'});
quit() if($options{'check-update'});
printIntroMsg() unless($options{'skip-intro'} || $options{'net-conf'} || $options{quiet});
print "\n";
printHeaderLine();
printTimestampLine();
if(! $options{'skip-net-conf'}) {
  getNetConf();
  if(! $options{quiet}) {
    netConfAnalysis();
    $crNeeded=1;
  }
}
quit() if($options{'net-conf'});

my $srvAs = $options{'alternate-srv'} ? '5410' : '12876';

my ($localDlSpeed,$localMaxThroughput,$internetBbrDlSpeed,$internetBbrMaxThroughput,$internetCubicDlSpeed,$internetCubicMaxThroughput,$internetUlSpeed,$internetUlMaxThroughput);

if(! $options{upload}) {
  if(! $options{'skip-freebox'}) {
    print "\n" if($crNeeded);
    ($localDlSpeed,$localMaxThroughput)=testTcp('local','IPv4');
    $crNeeded=1;
  }
  if(! $options{freebox}) {
    print "\n" if($crNeeded);
    ($internetBbrDlSpeed,$internetBbrMaxThroughput)=testTcp('Internet',$options{ipv6} ? 'IPv6' : 'IPv4','download',$srvAs,'BBR');
    if($options{'all-srv'}) {
      print "\n";
      my ($bbr2,$bbrMax2)=testTcp('Internet',$options{ipv6} ? 'IPv6' : 'IPv4','download',5410,'BBR');
      if($bbr2>$internetBbrDlSpeed) {
        $internetBbrDlSpeed=$bbr2;
        $internetBbrMaxThroughput=$bbrMax2;
      }
    }
    print "\n";
    ($internetCubicDlSpeed,$internetCubicMaxThroughput)=testTcp('Internet',$options{ipv6} ? 'IPv6' : 'IPv4','download',$srvAs,'CUBIC');
    if($options{'all-srv'}) {
      print "\n";
      my ($cubic2,$cubicMax2)=testTcp('Internet',$options{ipv6} ? 'IPv6' : 'IPv4','download',5410,'CUBIC');
      if($cubic2>$internetCubicDlSpeed) {
        $internetCubicDlSpeed=$cubic2;
        $internetCubicMaxThroughput=$cubicMax2;
      }
    }
    $crNeeded=1;
  }
}

quit() if($options{freebox});

if($options{upload}) {
  print "\n" if($crNeeded);
  ($internetUlSpeed,$internetUlMaxThroughput)=testTcp('Internet',$options{ipv6} ? 'IPv6' : 'IPv4','upload',$srvAs);
  if($options{'all-srv'}) {
    print "\n";
    my ($upload2,$uploadMax2)=testTcp('Internet',$options{ipv6} ? 'IPv6' : 'IPv4','upload',5410);
    if($upload2>$internetUlSpeed) {
      $internetUlSpeed=$upload2;
      $internetUlMaxThroughput=$uploadMax2;
    }
  }
  $crNeeded=1;
}

quit() if($options{quiet});

my $isBusyHour;
{
  my $localtime=Time::Piece::localtime();
  $isBusyHour = (any {$localtime->day_of_week() == $_} (0,7)) || $localtime->hour() > 17;
}

if(defined $localDlSpeed && $localDlSpeed < 70E6) {
  if((! defined $internetBbrDlSpeed || $internetBbrDlSpeed < 90E6)
     && (! defined $internetCubicDlSpeed || $internetCubicDlSpeed < 90E6)) {
    printDiag("[!] Débit local dégradé (le matériel utilisé pour les tests ne permet pas de vérifier complètement les capacités de la connexion FTTH)");
    if($options{suggestions}) {
      if($degradedTcpConf || (defined $localMaxThroughput && $localDlSpeed > 3 * $localMaxThroughput / 5)) {
        print "    Recommandation: ajuster le paramétrage réseau du système\n";
      }else{
        print "    Recommandation: vérifier qu'une liaison filaire est utilisée et que rien d'autre ne consomme de la bande passante ni du CPU sur le système\n";
      }
    }
  }else{
    printDiag("[!] Les performances du service de test de débit local de la Freebox sont dégradées");
    if($options{suggestions}) {
      print "    Recommandation: vérifier que rien d'autre ne consomme des ressources sur la Freebox (TV, téléchargements, Torrent...)\n";
    }
  }
}

my %congestionLevels=(1 => 'une forte perte de paquets',
                      4 => 'une perte de paquets prononcée',
                      7 => 'de la perte de paquets');
if(defined $internetBbrDlSpeed && defined $internetCubicDlSpeed) {
  my $cubicBbrRatio=$internetCubicDlSpeed/$internetBbrDlSpeed;
  my $congestionLevel;
  my @sortedCongestionLevels=sort keys %congestionLevels;
  for my $cl (@sortedCongestionLevels) {
    if($cubicBbrRatio < $cl/10) {
      $congestionLevel=$cl;
      last;
    }
  }
  if($congestionLevel) {
    $congestionLevel=$sortedCongestionLevels[-1] if($internetCubicDlSpeed > 100_000_000);
    my $percentRatio=sprintf('%.2f',$cubicBbrRatio*100).'%';
    printDiag('[!] La connexion aux serveurs de test semble affectée par '.$congestionLevels{$congestionLevel});
    printDiag("      (ratio débit CUBIC/BBR: $percentRatio)");
    if($options{suggestions}) {
      print '    Suggestion'.($isBusyHour?'s':'').":\n";
      print "      - vérifier que rien d'autre ne consomme de la bande passante\n";
      print "      - relancer le test le matin en semaine pour comparer les résultats\n" if($isBusyHour);
    }
  }
}

quit();
