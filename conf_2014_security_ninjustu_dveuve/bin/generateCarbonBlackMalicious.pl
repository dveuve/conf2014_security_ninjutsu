#!/usr/bin/perl
use Date::Calc qw(Add_Delta_Days Mktime);

my $SPLUNK_HOME = "/opt/splunk";

my $startdate = "2014-04-01";


my @timedata = localtime(time);

my $maxdate = (1900 + $timedata[5]) ."-" . LeadingZero($timedata[4] + 1) ."-". LeadingZero($timedata[3]);

my $root = "$SPLUNK_HOME/etc/apps/conf_2014_security_ninjustu_dveuve/log/CarbonBlack";



my @staffids = ();
my $staff;
initstaff();
print "Got " . @staffids . " staff ids\n";
my $pguid = {};
my @Programs;
GeneratePaths();

my $day = $maxdate;

        $day =~ /^(\d{4})-(\d\d)-(\d\d)$/;
        $yr = $1;
        $mn = $2;
        $da = $3;

        print "\t $yr $mn $da - ";

        ($yr, $mn, $da) = Add_Delta_Days($yr, $mn, $da, -1);
        print "Got $day, resulted in $yr $mn $da \n";
        $day = $yr . "-" . LeadingZero($mn) . "-" . LeadingZero($da);



#until($day eq "2014-04-06"){
	
open(FOUT, ">" . $root . $day . "-malicious.log");

    my $hr = 12;
    my $min = 15;
    my $sec = 47;
	$day =~ /^(\d{4})-(\d*)-(\d*)$/;
	my $yr = $1;
	my $mn = $2;
	my $da = $3;
	#my $DateString = $day . " " . LeadingZero($hr) . ":" . LeadingZero($min) . ":" . LeadingZero($sec) . "." . LeadingZero(int(rand(60))); #2013-09-16 23:40:56.00
	for(my $i = 0; $i < 2; $i++){
		$min++;
		$sec = int(rand(60));

		my $DateString = Mktime($yr, $mn, $da, $hr, $min, $sec);
		my $empid = $staffids[$i];
		my $emphostname = uc( $staff->{$empid}->{hostname} );
		#my $empname = $staff->{$empid}->{name};
		#my $emprole = $staff->{$empid}->{role};
		#my $emproleid = $staff->{$empid}->{roleid};
		my $prog = $i;
		$progpath = $Programs[$prog]->{path};
		$progmd5 = $Programs[$prog]->{md5};
		$guid = int(rand(40000000000));
		$pguid = $pguid{$empid} || 0; 
		if(int(rand(10)) == 7){$pguid = 0;}
		if(int(rand(3)) == 2){ $pguid{$empid} = $guid };
		#print "Running with $empid - $guid - $pguid\n";
		#print "Running with $DateString, $empid, $empuser $empname, $emprole, $emproleid, $patid, $patname\n";
		print  FOUT GetCBLog($DateString, $emphostname, $progpath, $progmd5, $pguid, $guid) . "\n";

		
	}
	

close(FOUT);
    



sub SomeRandom{
	return 1 + rand(0.2)- 0.1;
}

sub VeryRandom{
	return rand(3);
}

sub GetCBLog {
	my $DateString = shift;
	my $emphostname = shift;
	my $progpath = shift;
	my $progmd5 = shift;
	my $pguid = shift;
	my $guid = shift;
	$progpath =~ s/\\/\\\\/g;
	#return "$DateString - $emphostname - $progpath - $progmd5 - $pguid - $guid\n";
	my $Writestring = '***SPLUNK*** host="HOST"' . "\n" . '{"action": "write", "timestamp": TIME, "path": "PATH", "type": "filemod", "process_guid": PGUID}';
	$Writestring =~ s/TIME/$DateString/;
	$Writestring =~ s/PATH/$progpath/;
	$Writestring =~ s/PGUID/$guid/;
	$Writestring =~ s/HOST/$emphostname/;
	return $Writestring;
}


sub initstaff{

	$staff->{123211}->{name} = "Travis Parks";
	$staff->{123211}->{hostname} = "TPARKS-31919b";
	$staff->{123211}->{role} = "Administrator Payroll";
	$staff->{123211}->{freq} = 1;
	$staff->{115441}->{name} = "Joanna Christian";
	$staff->{115441}->{hostname} = "JCHRIST-86217c";
	$staff->{115441}->{role} = "Payroll Clerk";
	$staff->{115441}->{freq} = 1;


	foreach my $key (keys %{$staff}){
		
		for(my $i = 0; $i < $staff->{$key}->{freq}; $i++){
			$staffids[@staffids] = $key;

		}
	}

}


sub GeneratePaths{
	
	$Programs[0]->{path} = 'C:\Users\administrator\calc.exe';
	$Programs[1]->{path} = 'C:\Windows\System32\outlook.exe';
	
	
}

sub LeadingZero{
        my $num = shift;
        my $digits = shift || 2;

        while(length($num) < $digits){
                $num = "0" . $num;
        }

        return $num;
}

