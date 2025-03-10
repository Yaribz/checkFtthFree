#!/usr/bin/env perl
#
# checkFtthFree
# Copyright (C) 2023-2025 Yann Riou <yaribzh@gmail.com>
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
  DARWIN => $^O eq 'darwin',
  LINUX => $^O eq 'linux',
  MSWIN32 => $^O eq 'MSWin32',
  OPENBSD => $^O eq 'openbsd',
};

require HTTP::Tiny;
require Net::Ping;
{
  no warnings 'once';
  $Net::Ping::pingstring="PING\n";
}
require POSIX;
require Time::Piece;

my ($SYSCTL_CMD_PATH,$IP_CMD_PATH,$ETHTOOL_CMD_PATH,$ROUTE_CMD_PATH,$IFCONFIG_CMD_PATH,$NETSTAT_CMD_PATH);
if(! MSWIN32) {
  $SYSCTL_CMD_PATH=findCmd('sysctl');
  if(LINUX) {
    ($IP_CMD_PATH,$ETHTOOL_CMD_PATH)=(map {findCmd($_)} (qw'ip ethtool'));
  }else{
    ($ROUTE_CMD_PATH,$IFCONFIG_CMD_PATH,$NETSTAT_CMD_PATH)=(map {findCmd($_)} (qw'route ifconfig netstat'))
  }
}
sub findCmd {
  my $cmd=shift;
  foreach my $knownPath (map {$_.'/'.$cmd} (qw'/sbin /usr/sbin /bin /usr/bin')) {
    return $knownPath if(-f $knownPath && -r _ && -x _);
  }
  require IPC::Cmd;
  return IPC::Cmd::can_run($cmd);
}

my $VERSION='0.27';
my $PROGRAM_NAME='checkFtthFree';

my $IPV6_COMPAT=eval { require IO::Socket::IP; IO::Socket::IP->VERSION(0.25) };

my %TEST_DATA = (
  local => {
    timeout => 2,
    latencyWarningThreshold => 10,
    servers => {
      Freebox => ['212.27.38.253','[fd0f:ee:b0::1]',8095,'/fixed/10G'],
    },
  },
  Internet => {
    timeout => 8,
    latencyWarningThreshold => 30,
    servers => {
      Scaleway => ['ping.online.net','ping6.online.net',80,'/10000Mo.dat','BBR'],
      Appliwave => ['ipv4.appliwave.testdebit.info','ipv6.appliwave.testdebit.info',80,'/10G.iso','BBR'],
    },
  },
    );

my $MTU=1500;
my $MSS=$MTU-40;
my $TCP_EFFICIENCY=$MSS/($MTU+38);
my $GOODPUT_1Gbps_Bytes=1_000_000_000*$TCP_EFFICIENCY/8;
my $GOODPUT_700Mbps_Bytes=700_000_000*$TCP_EFFICIENCY/8;
my $RECOMMENDED_MIN_RTT_MAX_FOR_FULL_BANDWIDTH=15;
my $RECOMMENDED_MIN_RCV_WINDOW_SIZE=$GOODPUT_1Gbps_Bytes*$RECOMMENDED_MIN_RTT_MAX_FOR_FULL_BANDWIDTH/1000;
my $RECOMMENDED_MIN_SND_WINDOW_SIZE=$GOODPUT_700Mbps_Bytes*$RECOMMENDED_MIN_RTT_MAX_FOR_FULL_BANDWIDTH/1000;

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
             'alternate-srv' => ["Change de serveur pour les tests Internet (utilise Appliwave au lieu de Scaleway)",'a'],
             'all-srv' => ['Effectue les tests Internet en double, une fois avec chaque serveur','A'],
             'binary-units' => ["Utilise les préfixes binaires pour le système d'unités de débit",'b'],
             'extended-test' => ['Effectue des tests plus longs (multiplie par 2 la durée max des tests)','e'],
             'quiet' => ["Mode silencieux: désactive les messages d'analyse et d'avertissement",'q'],
             help => ["Affiche l'aide",'h'],
             version => ['Affiche la version','v'],
             ipv6 => ['Effectue les tests Internet en IPv6 (IPv4 par défaut)','6'],
             'all-ipv' => ['Effectue tous les tests en double, une fois en IPv4 et une fois en IPv6','2']);
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
                                                         ['ipv6','all-ipv'],
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
  }elsif(defined $SYSCTL_CMD_PATH) {
    my @netConfFields;
    if(LINUX) {
      if(defined $IP_CMD_PATH) {
        my @cmdOutputLines = $options{ipv6} ? `$IP_CMD_PATH -6 route show default 2>/dev/null` : `$IP_CMD_PATH -4 route show default 2>/dev/null`;
        my $device;
        foreach my $line (@cmdOutputLines) {
          if($line =~ /\sdev\s+([^\s\/]{1,15})\s/) {
            $device=$1;
            last;
          }
        }
        if(defined $device) {
          @cmdOutputLines=`$IP_CMD_PATH link show $device 2>/dev/null`;
          my %devices = defined $cmdOutputLines[0] && $cmdOutputLines[0] =~ /^\d+\s*:\s*\Q$device\E\@([^\s\/]{1,15})\s*:/ ? (intf => $1, vlan => $device) : (intf => $device);
          my $activeDevice=getFileFirstLine("/sys/class/net/$devices{intf}/bonding/active_slave");
          @devices{'bonding','intf'}=($devices{intf},$activeDevice) if(defined $activeDevice);
          $netConf{$_.'.dev'}=$devices{$_} foreach(keys %devices);
          my %INTF_SETTINGS = map {$_ => 1} (qw'mtu qdisc qlen');
          foreach my $devType (keys %devices) {
            my $dev=$devices{$devType};
            @cmdOutputLines=`$IP_CMD_PATH link show $dev 2>/dev/null`;
            foreach my $line (@cmdOutputLines) {
              next unless($line =~ /\s(mtu\s.*)$/);
              my @linkSettings=split(/\s+/,$1);
              last if(@linkSettings % 2);
              for my $i (0..$#linkSettings/2) {
                my ($linkSettingName,$linkSettingValue)=($linkSettings[$i*2],$linkSettings[$i*2+1]);
                next unless($INTF_SETTINGS{$linkSettingName});
                $netConf{"$devType.$linkSettingName"}=$linkSettingValue;
              }
              last;
            }
          }
          if(defined $ETHTOOL_CMD_PATH) {
            { # General info
              @cmdOutputLines=`$ETHTOOL_CMD_PATH $devices{intf} 2>/dev/null`;
              my %ETHTOOL_PARAM_MAPPING=(
                speed => 'speed',
                duplex => 'duplex',
                'auto-negotiation' => 'autoneg',
                port => 'port',
                  );
              foreach my $line (@cmdOutputLines) {
                next unless($line =~ /^\s*([^:]*[^:\s])\s*:\s*(.*[^\s])\s*$/);
                my ($lcParam,$val)=(lc($1),$2);
                next unless(exists $ETHTOOL_PARAM_MAPPING{$lcParam});
                $netConf{'link.'.$ETHTOOL_PARAM_MAPPING{$lcParam}}=$val;
              }
            }
            { # Driver
              @cmdOutputLines=`$ETHTOOL_CMD_PATH -i $devices{intf} 2>/dev/null`;
              my %driverInfo;
              foreach my $line (@cmdOutputLines) {
                $driverInfo{lc($1)}=$2 if($line =~ /^\s*([^:]*[^\s:])\s*:\s*(.*[^\s])\s*$/);
              }
              if(exists $driverInfo{driver}) {
                $netConf{'intf.driver'}=$driverInfo{driver};
                $netConf{'intf.driver'}.=" $driverInfo{version}" if(exists $driverInfo{version});
              }
              $netConf{'intf.firmware-version'}=$driverInfo{'firmware-version'} if(exists $driverInfo{'firmware-version'});
            }
            { # Coalescing
              @cmdOutputLines=`$ETHTOOL_CMD_PATH -c $devices{intf} 2>/dev/null`;
              my ($adaptiveRx,$rxUsecs,$rxFrames,$adaptiveTx,$txUsecs,$txFrames);
              foreach my $line (@cmdOutputLines) {
                if($line =~ /^\s*adaptive[\- ]rx\s*:\s*([^\s]+)(?:\s+tx\s*:\s*([^\s]+))?\s*$/i) {
                  $adaptiveRx=$1;
                  $adaptiveTx=$2 if(defined $2);
                }elsif($line =~ /^\s*adaptive[\- ]tx\s*:\s*([^\s]+)(?:\s+rx\s*:\s*([^\s]+))?\s*$/i) {
                  $adaptiveTx=$1;
                  $adaptiveRx=$2 if(defined $2);
                }elsif($line =~ /^\s*rx[\- ]usecs\s*:\s*(\d+)\s*$/i) {
                  $rxUsecs=$1;
                }elsif($line =~ /^\s*tx[\- ]usecs\s*:\s*(\d+)\s*$/i) {
                  $txUsecs=$1;
                }elsif($line =~ /^\s*rx[\- ]frames\s*:\s*(\d+)\s*$/i) {
                  $rxFrames=$1;
                }elsif($line =~ /^\s*tx[\- ]frames\s*:\s*(\d+)\s*$/i) {
                  $txFrames=$1;
                }
              }
              if(defined $adaptiveRx && lc($adaptiveRx) eq 'on') {
                $netConf{'intf.coalesce-rx'}='adaptive';
              }else{
                my @rxVals;
                if(defined $adaptiveRx) {
                  my $lcAdaptiveRx=lc($adaptiveRx);
                  push(@rxVals,'adaptive='.$lcAdaptiveRx)
                      unless(any {$lcAdaptiveRx eq $_} (qw'off n/a'));
                }
                push(@rxVals,$rxUsecs.' usecs') if(defined $rxUsecs);
                push(@rxVals,$rxFrames.' frames') if(defined $rxFrames);
                $netConf{'intf.coalesce-rx'}=join(' / ',@rxVals) if(@rxVals);
              }
              if(defined $adaptiveTx && lc($adaptiveTx) eq 'on') {
                $netConf{'intf.coalesce-tx'}='adaptive';
              }else{
                my @txVals;
                if(defined $adaptiveTx) {
                  my $lcAdaptiveTx=lc($adaptiveTx);
                  push(@txVals,'adaptive='.$lcAdaptiveTx)
                      unless(any {$lcAdaptiveTx eq $_} (qw'off n/a'));
                }
                push(@txVals,$txUsecs.' usecs') if(defined $txUsecs);
                push(@txVals,$txFrames.' frames') if(defined $txFrames);
                $netConf{'intf.coalesce-tx'}=join(' / ',@txVals) if(@txVals);
              }
            }
            { # Ring buffer
              @cmdOutputLines=`$ETHTOOL_CMD_PATH -g $devices{intf} 2>/dev/null`;
              my ($currentSection,%ringValues);
              foreach my $line (@cmdOutputLines) {
                if($line =~ /\smaximums\s*:\s*$/i) {
                  $currentSection='max';
                }elsif($line =~ /^current\s.*:\s*$/i) {
                  $currentSection='current';
                }elsif(defined $currentSection && $line =~ /^\s*([rt]x)\s*:\s*([^\s]+)\s*$/i) {
                  $ringValues{uc($1)}{$currentSection}=$2;
                }
              }
              if(exists $ringValues{RX} && exists $ringValues{RX}{current}) {
                $netConf{'intf.ring-rx'}=$ringValues{RX}{current};
                $netConf{'intf.ring-rx'}.=" (max: $ringValues{RX}{max})" if(exists $ringValues{RX}{max});
              }
              if(exists $ringValues{TX} && exists $ringValues{TX}{current}) {
                $netConf{'intf.ring-tx'}=$ringValues{TX}{current};
                $netConf{'intf.ring-tx'}.=" (max: $ringValues{TX}{max})" if(exists $ringValues{TX}{max});
              }
            }
            { # Offloading and features
              @cmdOutputLines=`$ETHTOOL_CMD_PATH -k $devices{intf} 2>/dev/null`;
              my %ETHTOOL_PARAM_MAPPING=(
                'rx-checksumming' => 'cksum_rx',
                'tx-checksumming' => 'cksum_tx',
                'tcp-segmentation-offload' => 'tso',
                'generic-segmentation-offload' => 'gso',
                'generic-receive-offload' => 'gro',
                'large-receive-offload' => 'lro',
                  );
              my @offloaded;
              foreach my $line (@cmdOutputLines) {
                next unless($line =~ /^\s*([^:]*[^\s:])\s*:\s*([^\[]*[^\s\[])(?:\s+\[[^\]]*\])?\s*$/);
                my $lcParam=lc($1);
                if($lcParam eq 'scatter-gather') {
                  $netConf{'intf.dma-sg'}=$2;
                }elsif(exists $ETHTOOL_PARAM_MAPPING{$lcParam}) {
                  my ($lcVal,$mappedVal)=(lc($2),$ETHTOOL_PARAM_MAPPING{$lcParam});
                  if($lcVal eq 'on') {
                    push(@offloaded,'+'.$mappedVal);
                  }elsif(any {$lcVal eq $_} (qw'off n/a')) {
                    push(@offloaded,'-'.$mappedVal);
                  }else{
                    push(@offloaded,$mappedVal.'='.$2);
                  }
                }
              }
              $netConf{'intf.offload'}=join(' | ',@offloaded) if(@offloaded);
            }
          }
          foreach my $linkParam (qw'duplex speed') {
            my $fullParam='link.'.$linkParam;
            next if(defined $netConf{$fullParam});
            my $val=getFileFirstLine("/sys/class/net/$devices{intf}/$linkParam");
            $netConf{$fullParam}=$val if(defined $val);
          }
          my %SYSCLASS_PARAM_MAPPING=(mtu => 'mtu', tx_queue_len => 'qlen');
          foreach my $intfParam (keys %SYSCLASS_PARAM_MAPPING) {
            my $fullParam='intf.'.$SYSCLASS_PARAM_MAPPING{$intfParam};
            next if(defined $netConf{$fullParam});
            my $val=getFileFirstLine("/sys/class/net/$devices{intf}/$intfParam");
            $netConf{$fullParam}=$val if(defined $val);
          }
          my %SYSCLASS_DEVICE_PARAM_MAPPING=(current_link_speed => 'link_speed', current_link_width => 'link_width');
          foreach my $intfParam (keys %SYSCLASS_DEVICE_PARAM_MAPPING) {
            my $val=getFileFirstLine("/sys/class/net/$devices{intf}/device/$intfParam");
            $netConf{'dev.'.$SYSCLASS_DEVICE_PARAM_MAPPING{$intfParam}}=$val if(defined $val);
          }
        }
      }
      my $r_netErrors=linuxGetNetErrorCounters($netConf{'intf.dev'});
      %netAdapterErrors=%{$r_netErrors};
      @netConfFields=qw'
          net.core.default_qdisc
          net.core.netdev_budget
          net.core.netdev_budget_usecs
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
      if(defined $ROUTE_CMD_PATH) {
        my @cmdOutputLines = $options{ipv6} ? `$ROUTE_CMD_PATH -n get -inet6 default` : `$ROUTE_CMD_PATH -n get default`;
        my $device;
        foreach my $line (@cmdOutputLines) {
          if($line =~ /^\s*interface\s*:\s*([^\s\/]{1,15})\s*$/) {
            $device=$1;
            last;
          }
        }
        if(defined $device) {
          $netConf{'intf.dev'}=$device;
          if(defined $IFCONFIG_CMD_PATH) {
            my $ifConfigFlag = DARWIN ? '-v ' : '';
            my @ifconfigCmdRes = `$IFCONFIG_CMD_PATH $ifConfigFlag$device`;
            my %IFCONFIG_PARAM_MAPPING=(media => 'link.media', type => 'link.type', scheduler => 'intf.qdisc', 'link rate' => 'link.speed');
            my (@enabledOpts,%enabledOptsDedup);
            foreach my $line (@ifconfigCmdRes) {
              if(! exists $netConf{'intf.mtu'} && $line =~ /\smtu\s(\d+)/) {
                $netConf{'intf.mtu'}=$1;
              }elsif($line =~ /^\s*(?:options|enabled|ec_enabled)\s*=\s*[\da-fA-F]+\s*<([^>]+)>\s*/) {
                foreach my $opt (split(/,/,$1)) {
                  next if(lc(substr($opt,0,5)) eq 'vlan_' || exists $enabledOptsDedup{$opt});
                  $enabledOptsDedup{$opt}=1;
                  push(@enabledOpts,$opt);
                }
              }elsif($line =~ /^\s*([\w ]*[^\s])\s*:\s*(.*[^\s])\s*$/ && exists $IFCONFIG_PARAM_MAPPING{$1}) {
                $netConf{$IFCONFIG_PARAM_MAPPING{$1}}=$2;
              }
            }
            $netConf{'intf.options'}=join(',',@enabledOpts) if(@enabledOpts);
          }
          my $r_intfErrors=bsdGetIntfErrorCounters($device);
          %netAdapterErrors=%{$r_intfErrors};
        }
      }
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
          net.inet.tcp.ecn_initiate_out
          net.inet.tcp.ecn_negotiate_in
          net.inet6.ip6.ifq.maxlen
          net.inet6.ip6.intr_queue_maxlen
          net.link.generic.system.rcvq_maxlen
          net.link.generic.system.sndq_maxlen
          net.link.ifqmaxlen';
    }
    my @netConfLines=`$SYSCTL_CMD_PATH -a 2>/dev/null`;
    foreach my $line (@netConfLines) {
      if($line =~ /^\s*([^:=]*[^\s:=])\s*[:=]\s*(.*[^\s])\s*$/ && (any {$1 eq $_} @netConfFields)) {
        $netConf{$1}=$2;
      }
    }
  }
}

sub getFileFirstLine {
  my $filePath=shift;
  my $fileHdl;
  return unless(-f $filePath && -r _ && open($fileHdl,'<',$filePath));
  my $content=<$fileHdl>;
  close($fileHdl);
  return unless(defined $content);
  chomp($content);
  return if($content eq '');
  return $content;
}

sub linuxGetNetErrorCounters {
  my $dev=shift;
  my %errorCounters;
  if(defined $dev) {
    my $devStatDir="/sys/class/net/$dev/statistics";
    if(-d $devStatDir && -r _ && opendir(my $statDh,$devStatDir)) {
      my @errorCounterNames = grep {(/_errors$/ || /_dropped$/ || $_ eq 'collisions') &&  -f "$devStatDir/$_" && -r _} readdir($statDh);
      closedir($statDh);
      foreach my $errorCounter (@errorCounterNames) {
        my $counterFh;
        next unless(open($counterFh,'<',"$devStatDir/$errorCounter"));
        my $counterValue=<$counterFh>;
        close($counterFh);
        next unless(defined $counterValue && $counterValue =~ /^(\d+)/);
        $errorCounters{$errorCounter}=$1;
      }
    }
  }
  my $softnetStatFile='/proc/net/softnet_stat';
  if(-f $softnetStatFile && -r _ && open(my $softnetStatFh,'<',$softnetStatFile)) {
    while(my $statLine=<$softnetStatFh>) {
      next unless($statLine =~ /^[\da-fA-F]+\s+([\da-fA-F]+)\s+([\da-fA-F]+)/);
      $errorCounters{rx_softnet_dropped}+=hex('0x'.$1);
      $errorCounters{rx_softnet_squeezed}+=hex('0x'.$2);
    }
    close($softnetStatFh);
  }
  return \%errorCounters;
}

sub bsdGetIntfErrorCounters {
  return {} unless(defined $NETSTAT_CMD_PATH);
  my $dev=shift;
  my $r_linkCounters=bsdGetLinkCounters($dev);
  if(OPENBSD) {
    my $r_linkErrorCounters=bsdGetLinkCounters($dev,'e');
    $r_linkCounters->{$_}//=$r_linkErrorCounters->{$_} foreach(keys %{$r_linkErrorCounters});
  }
  my %errorCounters;
  foreach my $counter (keys %{$r_linkCounters}) {
    next unless($counter =~ /^colls?$/i
                || $counter =~ /^[io]?drops?$/i
                || $counter =~ /^[io]errs$/i);
    next unless($r_linkCounters->{$counter} =~ /^\d+$/);
    $errorCounters{$counter}=$r_linkCounters->{$counter};
  }
  return \%errorCounters;
}

sub bsdGetLinkCounters {
  my ($dev,$flag)=@_;
  $flag//='d';
  my @cmdOutputLines=`$NETSTAT_CMD_PATH -${flag}nI $dev 2>/dev/null`;
  my @fieldNames;
  foreach my $line (@cmdOutputLines) {
    chomp($line);
    next if($line =~ /^\s*$/);
    if(@fieldNames) {
      my @vals=split(/\s+/,$line);
      my %data;
      $data{$fieldNames[$_]}=$vals[$_] for(0..$#fieldNames);
      next unless(exists $data{Network} && substr(lc($data{Network}),0,5) eq '<link');
      return \%data;
    }else{
      @fieldNames=split(/\s+/,$line);
    }
  }
  return {};
}

my ($rcvWindow,$rmemMax,$rmemMaxParam,$rmemMaxValuePrefix,$tcpAdvWinScale);
my ($sndWindow,$wmemMax,$wmemMaxParam,$wmemMaxValuePrefix);
my ($degradedTcpConf,$suggestionForRcvWindowPrinted,$suggestionForSndWindowPrinted,$warningForTcpBufferPrinted);
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
      $rmemMaxParam='AutoTuningLevelLocal';
    }elsif(defined $netConf{AutoTuningLevelGroupPolicy}) {
      $rmemMaxParam='AutoTuningLevelGroupPolicy';
    }
    if(defined $rmemMaxParam) {
      processWindowsAutoTuningLevel($rmemMaxParam);
      if($netConf{$rmemMaxParam} ne 'Normal' && $netConf{$rmemMaxParam} ne 'Experimental') {
        if($rmemMaxParam eq 'AutoTuningLevelLocal') {
          print "[!] La valeur actuelle de AutoTuningLevelLocal peut dégrader les performances\n";
          if($options{suggestions}) {
            print "    Recommandation: ajuster le paramètre en utilisant l'une des deux commandes suivantes\n";
            print "      [PowerShell] Set-NetTCPSetting -SettingName Internet -AutoTuningLevelLocal Normal\n";
            print "      [cmd.exe] netsh interface tcp set global autotuninglevel=normal\n";
            $suggestionForRcvWindowPrinted=1;
          }
        }else{
          print "[!] La stratégie de groupe appliquée aux paramètres AutoTuningLevelEffective et AutoTuningLevelGroupPolicy peut dégrader les performances\n";
          if($options{suggestions}) {
            print "    Recommandation: effectuer l'une des deux actions suivantes\n";
            print "      - configurer la valeur du paramètre AutoTuningLevelGroupPolicy à \"Normal\" dans la stratégie de groupe\n";
            print "      - utiliser la configuration locale pour ce paramètre (configurer le valeur du paramètre AutoTuningLevelEffective à \"Local\")\n";
            $suggestionForRcvWindowPrinted=1;
          }
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
      checkPcieLinkSpeedConsistency('LinkSpeed','PcieLinkSpeed','PcieLinkWidth');
    }
  }else{
    map {print "  $_: $netConf{$_}\n"} (sort keys %netConf);
    if(LINUX) {
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
      $sndWindow=wmemToSndWindowValue($wmemMax) if(defined $wmemMax);
      if(exists $netConf{'link.speed'}
         && exists $netConf{'dev.link_speed'} && $netConf{'dev.link_speed'} ne 'Unknown'
         && exists $netConf{'dev.link_width'} && $netConf{'dev.link_width'}) {
        checkPcieLinkSpeedConsistency('link.speed','dev.link_speed','dev.link_width');
      }
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
    print "  => Latence max pour une réception TCP à 1 Gbps: ${maxRttMsFor1Gbps} ms\n";
    if(! MSWIN32 && $maxRttMsFor1Gbps < $RECOMMENDED_MIN_RTT_MAX_FOR_FULL_BANDWIDTH) {
      if(LINUX) {
        if($tcpAdvWinScale < -2) {
          print "[!] Les valeurs actuelles de net.ipv4.tcp_adv_win_scale et $rmemMaxParam peuvent dégrader les performances\n";
          if($options{suggestions}) {
            print "    Recommandation: ajuster au moins un de ces paramètres en utilisant l'une des deux commandes suivantes\n";
            print "      sysctl -w net.ipv4.tcp_adv_win_scale=".($tcpAdvWinScale+1)."\n";
            print "      sysctl -w $rmemMaxParam=".rcvWindowToRmemValue($RECOMMENDED_MIN_RCV_WINDOW_SIZE)."\n";
            $suggestionForRcvWindowPrinted=1;
          }
        }else{
          print "[!] La valeur actuelle de $rmemMaxParam peut dégrader les performances\n";
          if($options{suggestions}) {
            print "    Recommandation: ajuster le paramètre en utilisant la commande suivante\n";
            print "      sysctl -w $rmemMaxParam=".rcvWindowToRmemValue($RECOMMENDED_MIN_RCV_WINDOW_SIZE)."\n";
            $suggestionForRcvWindowPrinted=1;
          }
        }
      }else{
        print "[!] La valeur actuelle de $rmemMaxParam peut dégrader les performances\n";
      }
    }
  }
  if(defined $sndWindow) {
    my $maxRttMsFor700Mbps = int($sndWindow * 1000 / $GOODPUT_700Mbps_Bytes + 0.5);
    print "  => Latence max pour une émission TCP à 700 Mbps: ${maxRttMsFor700Mbps} ms\n";
    if($maxRttMsFor700Mbps < $RECOMMENDED_MIN_RTT_MAX_FOR_FULL_BANDWIDTH) {
      print "[!] La valeur actuelle de $wmemMaxParam peut dégrader les performances\n";
      if(LINUX && $options{suggestions}) {
        print "    Recommandation: ajuster le paramètre en utilisant la commande suivante\n";
        print "      sysctl -w $wmemMaxParam=".sndWindowToWmemValue($RECOMMENDED_MIN_SND_WINDOW_SIZE)."\n";
        $suggestionForSndWindowPrinted=1;
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

sub checkPcieLinkSpeedConsistency {
  my ($paramLinkSpeed,$paramPcieLinkSpeed,$paramPcieLinkWidth)=@_;
  my $linkSpeed;
  if($netConf{$paramLinkSpeed} =~ /^(\d+(?:\.\d)?) ?([KMGT]?)b[p\/]s$/) {
    $linkSpeed=$1;
    my $unitPrefix=$2;
    $linkSpeed*={K => 1E3, M => 1E6, G => 1E9, T => 1E12}->{$unitPrefix} if($unitPrefix);
  }elsif(LINUX && $netConf{$paramLinkSpeed} =~ /^\d+$/) {
    $linkSpeed = $netConf{$paramLinkSpeed} * 1E6;
  }else{
    print "[!] Valeur de $paramLinkSpeed non reconnue\n";
    return;
  }
  if($netConf{$paramPcieLinkSpeed} !~ /^(\d+(?:\.\d)?) GT\/s/) {
    print "[!] Valeur de $paramPcieLinkSpeed non reconnue\n";
    return;
  }
  my $pcieEfficiency;
  if($1 < 8) {
    $pcieEfficiency=4/5;
  }elsif($1 < 64) {
    $pcieEfficiency=64/65;
  }else{
    $pcieEfficiency=121/128;
  }
  my $pcieLinkSpeed = $1 * 1E9 * $pcieEfficiency;
  if($netConf{$paramPcieLinkWidth} !~ /^\d+$/) {
    print "[!] Valeur de $paramPcieLinkWidth non reconnue\n";
    return;
  }
  $pcieLinkSpeed*=$netConf{$paramPcieLinkWidth};
  if($pcieLinkSpeed < $linkSpeed) {
    print "[!] La carte réseau utilise actuellement une interface PCI Express avec un taux de transfert ne permettant pas d'atteindre le débit maximum du lien réseau\n";
    print "    Recommandation: connecter la carte réseau sur un autre slot PCI Express (consulter le manuel de la carte mère si besoin pour trouver un slot adéquat)\n"
        if($options{suggestions});
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
  my @wmemValues=(
    [131072,131072],
    [235929,262144],
    [471859,524288],
    [943718,1048576],
    [1677721,2097152],
    [2936012,4194304],
    [5033164,8388608],
      );
  my $newWmemValue;
  foreach my $r_wmemValues (@wmemValues) {
    next unless($newSndWindow<=$r_wmemValues->[0]);
    $newWmemValue=$r_wmemValues->[1];
    last;
  }
  $newWmemValue//=fixMemSize(2*$newSndWindow);
  $newWmemValue="\"$wmemMaxValuePrefix$newWmemValue\"" if(defined $wmemMaxValuePrefix);
  return $newWmemValue;
}

sub wmemToSndWindowValue {
  my $tcpWmemMax=shift;
  return 2*$tcpWmemMax if($tcpWmemMax <= 65536);
  return (3-$tcpWmemMax/65536)*$tcpWmemMax if($tcpWmemMax <= 131072);
  return (1.1-$tcpWmemMax/1310720)*$tcpWmemMax if($tcpWmemMax <= 262144);
  return 0.9*$tcpWmemMax if($tcpWmemMax <= 1048576);
  return (1-$tcpWmemMax/10485760)*$tcpWmemMax if($tcpWmemMax <= 2097152);
  return (0.9-$tcpWmemMax/20971520)*$tcpWmemMax if($tcpWmemMax <= 4194304);
  return (0.8-$tcpWmemMax/41943040)*$tcpWmemMax if($tcpWmemMax <= 8388608);
  return (0.7-$tcpWmemMax/83886080)*$tcpWmemMax if($tcpWmemMax <= 16777216);
  return $tcpWmemMax/2;
}

sub fixMemSize { return POSIX::ceil($_[0]/POSIX::BUFSIZ())*POSIX::BUFSIZ() }

sub checkNetAdapterErrors {
  return unless(%netAdapterErrors);
  my %newErrorCounters;
  if(MSWIN32) {
    my $defaultIp = $options{ipv6} ? '::0' : '0.0.0.0';
    my $powershellScript = (<<"END_OF_POWERSHELL_SCRIPT" =~ s/\n//gr);
\$ErrorActionPreference='silentlycontinue';
Get-NetAdapterStatistics -Name (Find-NetRoute -RemoteIpAddress $defaultIp)[0].InterfaceAlias | Format-List -Property OutboundDiscardedPackets, OutboundPacketErrors, ReceivedDiscardedPackets, ReceivedPacketErrors;
END_OF_POWERSHELL_SCRIPT
    my @statLines = win32PowershellExec($powershellScript);
    map {$newErrorCounters{$1}=$2 if(/^\s*([^:]*[^\s:])\s*:\s*(.*[^\s])\s*$/)} @statLines;
  }else{
    my $r_netErrors;
    if(LINUX) {
      $r_netErrors=linuxGetNetErrorCounters($netConf{'intf.dev'});
    }else{
      $r_netErrors=bsdGetIntfErrorCounters($netConf{'intf.dev'});
    }
    %newErrorCounters=%{$r_netErrors};
  }
  foreach my $errorCounter (sort keys %newErrorCounters) {
    next unless(exists $netAdapterErrors{$errorCounter} && $newErrorCounters{$errorCounter} > $netAdapterErrors{$errorCounter});
    print "[!] Le compteur \"$errorCounter\" ".(substr($errorCounter,0,11) eq 'rx_softnet_' ? 'du noyau' : "de l'interface réseau")." a été incrémenté de ".($newErrorCounters{$errorCounter}-$netAdapterErrors{$errorCounter})." pendant le test.\n";
    if($options{suggestions}) {
      print "    Recommandations:\n";
      if((MSWIN32 && substr($errorCounter,8) eq 'DiscardedPackets')
         || (LINUX && ($errorCounter =~ /_dropped$/ || $errorCounter =~ /_missed_errors$/ || $errorCounter eq 'rx_softnet_squeezed'))
         || (! MSWIN32 && ! LINUX && $errorCounter =~ /^[io]?drops?$/i)) {
        if($errorCounter eq 'rx_softnet_dropped') {
          print "      - augmenter la taille maximum des files d'attente du noyau associées aux interfaces réseau (net.core.netdev_max_backlog)\n";
        }elsif($errorCounter eq 'rx_softnet_squeezed') {
          print "      - augmenter le nombre maximum de paquets réseau traités (net.core.netdev_budget) et/ou le temps maximum de traitement des paquets réseau (net.core.netdev_budget_usecs) par cycle de traitement du noyau\n";
        }else{
          my $counterFirstLetterLowerCase=lc(substr($errorCounter,0,1));
          my $isReceiveCounter = $counterFirstLetterLowerCase eq ((MSWIN32 || LINUX) ? 'r' : 'i');
          $isReceiveCounter=1 if(DARWIN && $counterFirstLetterLowerCase eq 'd');
          print '      - augmenter la taille de la mémoire tampon '.($isReceiveCounter ? 'de réception' : "d'envoi")." de l'interface réseau\n";
        }
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
  my ($type,$provider,$isIpv6,$isUpload)=@_;

  my $ipVer='IPv'.($isIpv6?6:4);
  my $testDescription="Test TCP $type ($ipVer): ";
  
  my ($hostIpv4,$hostIpv6,$testPort,$testPath,$cca)=@{$TEST_DATA{$type}{servers}{$provider}};
  my $testHost = $isIpv6 ? $hostIpv6 : $hostIpv4;
  
  if($type eq 'local') {
    $testDescription.=($options{latency}?'':'téléchargement depuis la ').'Freebox';
  }else{
    $testDescription .= $isUpload ? 'envoi vers le ' : 'téléchargement depuis le ' unless($options{latency});
    $testDescription.="serveur $provider";
    if($isUpload) {
      my $uploadCca=uc($netConf{CongestionProvider}//$netConf{'net.ipv4.tcp_congestion_control'});
      $testDescription.=" [$uploadCca]" if(defined $uploadCca);
    }else{
      $testDescription.=" [$cca]" if(defined $cca);
    }
  }
  
  print "$testDescription\n";

  my ($r_checkMaxThroughputForLatency,$r_getSpeed);
  if($type eq 'local' || ! $isUpload) {
    ($r_checkMaxThroughputForLatency,$r_getSpeed)=(\&checkMaxRcvThroughputForLatency,\&getDlSpeed);
  }else{
    ($r_checkMaxThroughputForLatency,$r_getSpeed)=(\&checkMaxSndThroughputForLatency,\&getUlSpeed);
  }
  
  my ($speed,$maxThroughput);

  $warningForTcpBufferPrinted=0;
  if(! $options{'skip-latency'}) {
    my ($rttMs,$jitter)=getTcpLatency($testHost,$testPort,$ipVer,$TEST_DATA{$type}{timeout},$maxNbPings);
    if(! defined $rttMs) {
      if($type eq 'local') {
        print "[!] Echec du test de latence\n";
        print "    En cas d'absence de Freebox, le paramètre --skip-freebox (-F) peut être utilisé pour désactiver le test local\n" unless($options{quiet});
        return undef;
      }else{
        quit('[!] Echec du test de latence');
      }
    }
    print "  --> Latence: $rttMs ms\t\t\t[gigue: $jitter ms]\n";
    print '[!] Latence élevée pour une connexion '.($type eq 'local' ? 'locale' : 'FTTH')."\n" if(! $options{quiet} && $rttMs > $TEST_DATA{$type}{latencyWarningThreshold});
    $maxThroughput=$r_checkMaxThroughputForLatency->(getEffectiveRttFromTcpConnectLatency($rttMs));
  }
  
  if(! $options{latency}) {
    $httpClient->{timeout}=$TEST_DATA{$type}{timeout};
    my $r_chunksData;
    ($speed,$r_chunksData)=$r_getSpeed->("http://$testHost:$testPort".($isUpload?'/':$testPath));
    if(! defined $speed) {
      if($type eq 'local' && $options{'skip-latency'}) {
        print "[!] Echec du test de débit\n";
        print "    En cas d'absence de Freebox, le paramètre --skip-freebox (-F) peut être utilisé pour désactiver le test local\n" unless($options{quiet});
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
    if(defined $maxThroughput && $speed > 4*$maxThroughput/5 && ! $warningForTcpBufferPrinted) { # $maxThroughput is only defined if $options{quiet} is false
      print "[!] Le débit pourrait avoir été limité par le paramétrage de la mémoire tampon TCP du système\n";
      if($options{suggestions}
         && (($isUpload && ! $suggestionForSndWindowPrinted)
             || (! $isUpload && ! $suggestionForRcvWindowPrinted))) {
        if(MSWIN32) { # On Windows, $maxThroughput is only defined for download tests
          if($rmemMaxParam eq 'AutoTuningLevelLocal') {
            print "    Suggestion: ajuster le paramètre AutoTuningLevelLocal en utilisant l'une des deux commandes suivantes\n";
            print "      [PowerShell] Set-NetTCPSetting -SettingName Internet -AutoTuningLevelLocal Experimental\n";
            print "      [cmd.exe] netsh interface tcp set global autotuninglevel=experimental\n";
          }else{
            print "    Suggestion: effectuer l'une des deux actions suivantes\n";
            print "      - configurer la valeur du paramètre AutoTuningLevelGroupPolicy à \"Experimental\" dans la stratégie de groupe\n";
            print "      - utiliser la configuration locale pour ce paramètre (configurer le valeur du paramètre AutoTuningLevelEffective à \"Local\")\n";
          }
          $suggestionForRcvWindowPrinted=1;
        }elsif(LINUX) {
          if($isUpload) {
            my $recommendedValue=getIncreasedTcpBufVal($wmemMax);
            $recommendedValue="\"$wmemMaxValuePrefix$recommendedValue\"" if(defined $wmemMaxValuePrefix);
            print "    Suggestion: augmenter la mémoire tampon max en utilisant la commande suivante\n";
            print "      sysctl -w $wmemMaxParam=$recommendedValue\n";
            $suggestionForSndWindowPrinted=1;
          }else{
            my $recommendedValue=getIncreasedTcpBufVal($rmemMax);
            $recommendedValue="\"$rmemMaxValuePrefix$recommendedValue\"" if(defined $rmemMaxValuePrefix);
            if($tcpAdvWinScale < -2) {
              print "    Suggestion: ajuster le paramétrage réseau du système en utilisant l'une des deux commandes suivantes\n";
              print "      sysctl -w net.ipv4.tcp_adv_win_scale=".($tcpAdvWinScale+1)."\n";
            }else{
              print "    Suggestion: augmenter la mémoire tampon max en utilisant la commande suivante\n";
            }
            print "      sysctl -w $rmemMaxParam=$recommendedValue\n";
            $suggestionForRcvWindowPrinted=1;
          }
        }else{
          print "    Suggestion: augmenter la mémoire tampon max en appliquant le changement de configuration suivant\n";
          if($isUpload) {
            print "      $wmemMaxParam = ".getIncreasedTcpBufVal($sndWindow)."\n";
            $suggestionForSndWindowPrinted=1;
          }else{
            print "      $rmemMaxParam = ".getIncreasedTcpBufVal($rcvWindow)."\n";
            $suggestionForRcvWindowPrinted=1;
          }
        }
      }
    }
  }
  
  checkNetAdapterErrors() unless($options{quiet});
  
  return ($speed,$maxThroughput);
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
  return undef unless($rcvWindow); # $rcvWindow is only defined if $options{quiet} is false
  my $latency=shift;
  my $maxThroughput=$rcvWindow*1000/$latency;
  if($maxThroughput < $GOODPUT_1Gbps_Bytes) {
    print "[!] Avec cette latence, le paramétrage actuel de mémoire tampon TCP pourrait limiter le débit en réception à environ ".readableSpeed($maxThroughput)."\n";
    $warningForTcpBufferPrinted=1;
    if(LINUX && $options{suggestions} && ! $suggestionForRcvWindowPrinted) {
      if($tcpAdvWinScale < -2) {
        print "    Recommandation: si la latence estimée est correcte, ajuster le paramétrage en utilisant l'une des deux commandes suivantes\n";
        print "      sysctl -w net.ipv4.tcp_adv_win_scale=".($tcpAdvWinScale+1)."\n";
      }else{
        print "    Recommandation: si la latence estimée est correcte, augmenter la mémoire tampon max en utilisant la commande suivante\n";
      }
      print "      sysctl -w $rmemMaxParam=".rcvWindowToRmemValue($GOODPUT_1Gbps_Bytes*$latency/1000)."\n";
      $suggestionForRcvWindowPrinted=1;
    }
  }
  return $maxThroughput;
}

sub checkMaxSndThroughputForLatency {
  return undef unless($sndWindow); # $sndWindow is only defined if $options{quiet} is false
  my $latency=shift;
  my $maxThroughput=$sndWindow*1000/$latency;
  if($maxThroughput < $GOODPUT_700Mbps_Bytes) {
    print "[!] Avec cette latence, le paramétrage actuel de mémoire tampon TCP pourrait limiter le débit en émission à environ ".readableSpeed($maxThroughput)."\n";
    if(LINUX && $options{suggestions} && ! $suggestionForSndWindowPrinted) {
      print "    Recommandation: si la latence estimée est correcte, augmenter la mémoire tampon max en utilisant la commande suivante\n";
      print "      sysctl -w $wmemMaxParam=".sndWindowToWmemValue($GOODPUT_700Mbps_Bytes*$latency/1000)."\n";
      $suggestionForSndWindowPrinted=1;
    }
  }
  return $maxThroughput;
}

sub getEffectiveRttFromTcpConnectLatency {
  my $rtt=shift;
  if(MSWIN32) {
    if($rtt > 23/9) {
      $rtt-=2.3;
    }else{
      $rtt/=10;
    }
  }else{
    if($rtt > 2.5) {
      $rtt-=1.5;
    }elsif($rtt > 1) {
      $rtt=$rtt/3+1/6;
    }else{
      $rtt/=2;
    }
  }
  return $rtt;
}

sub getIncreasedTcpBufVal {
  my $val=shift;
  my $increasedVal=1<<16;
  $increasedVal<<=1 while($val > 4*$increasedVal/5);
  return $increasedVal;
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
  if($uploadedSize) {
    quit("[!] Impossible d'évaluer le débit nominal (téléchargement trop court pour supprimer la phase de \"slow-start\")") unless($endTime > $startTime+$slowStartSkipDelay+1);
    my $ulSpeed=$uploadedSize/($endTime-$startTime);
    return wantarray() ? ($ulSpeed,\@chunkUlData) : $ulSpeed;
  }elsif($result->{success}) {
    quit("[!] Echec d'envoi vers \"$url\"");
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

my $srvProvider = $options{'alternate-srv'} ? 'Appliwave' : 'Scaleway';

my ($localDlSpeed,$localMaxThroughput,$internetBbrDlSpeed,$internetBbrMaxThroughput,$internetCubicDlSpeed,$internetCubicMaxThroughput,$internetUlSpeed,$internetUlMaxThroughput);

if(! $options{upload}) {
  if(! $options{'skip-freebox'}) {
    print "\n" if($crNeeded);
    # workaround for degraded Freebox perfs in IPv6: only do local IPv6 test when both IP versions are enabled, or when IPv6 is enabled in Freebox-only test mode
    ($localDlSpeed,$localMaxThroughput)=testTcp('local','Freebox',$options{ipv6} && $options{freebox});
    if($options{'all-ipv'}) {
      print "\n";
      my ($local2,$localMax2)=testTcp('local','Freebox',1);
      ($localDlSpeed,$localMaxThroughput)=($local2,$localMax2) if(defined $local2 && (! defined $localDlSpeed || $local2>$localDlSpeed));
    }        
    $crNeeded=1;
  }
  if(! $options{freebox}) {
    print "\n" if($crNeeded);
    ($internetBbrDlSpeed,$internetBbrMaxThroughput)=testTcp('Internet',$srvProvider,$options{ipv6});
    if($options{'all-ipv'}) {
      print "\n";
      my ($bbr2,$bbrMax2)=testTcp('Internet',$srvProvider,1);
      ($internetBbrDlSpeed,$internetBbrMaxThroughput)=($bbr2,$bbrMax2) if(defined $bbr2 && (! defined $internetBbrDlSpeed || $bbr2>$internetBbrDlSpeed));
    }
    if($options{'all-srv'}) {
      print "\n";
      my ($bbr2,$bbrMax2)=testTcp('Internet','Appliwave',$options{ipv6});
      ($internetBbrDlSpeed,$internetBbrMaxThroughput)=($bbr2,$bbrMax2) if(defined $bbr2 && (! defined $internetBbrDlSpeed || $bbr2>$internetBbrDlSpeed));
      if($options{'all-ipv'}) {
        print "\n";
        my ($bbr3,$bbrMax3)=testTcp('Internet','Appliwave',1);
        ($internetBbrDlSpeed,$internetBbrMaxThroughput)=($bbr3,$bbrMax3) if(defined $bbr3 && (! defined $internetBbrDlSpeed || $bbr3>$internetBbrDlSpeed));
      }
    }
#    print "\n";
#    ($internetCubicDlSpeed,$internetCubicMaxThroughput)=testTcp('Internet',$srvProviderCubic);
    $crNeeded=1;
  }
}

quit() if($options{freebox});

if($options{upload}) {
  print "\n" if($crNeeded);
  ($internetUlSpeed,$internetUlMaxThroughput)=testTcp('Internet',$srvProvider,$options{ipv6},1);
  if($options{'all-ipv'}) {
    print "\n";
    my ($upload2,$uploadMax2)=testTcp('Internet',$srvProvider,1,1);
    ($internetUlSpeed,$internetUlMaxThroughput)=($upload2,$uploadMax2) if($upload2>$internetUlSpeed);
  }
  if($options{'all-srv'}) {
    print "\n";
    my ($upload2,$uploadMax2)=testTcp('Internet','Appliwave',$options{ipv6},1);
    ($internetUlSpeed,$internetUlMaxThroughput)=($upload2,$uploadMax2) if($upload2>$internetUlSpeed);
    if($options{'all-ipv'}) {
      print "\n";
      my ($upload3,$uploadMax3)=testTcp('Internet','Appliwave',1,1);
      ($internetUlSpeed,$internetUlMaxThroughput)=($upload3,$uploadMax3) if($upload3>$internetUlSpeed);
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
