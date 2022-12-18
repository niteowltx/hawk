#include <stdio.h>
#include <unistd.h>
#include <stdlib.h>
#include <stdbool.h>
#include <ctype.h>
#include <string.h>
#include <sys/types.h>
#include <sys/stat.h>
#include <dirent.h>
#include <time.h>
#include <fcntl.h>

//	hawk --- watch processes for resource leaks

#define	BUFSIZE		1024
#define	TRIGGER_FILE	"/tmp/hawk_trigger"
#define	UNDEF		"UNDEF"			// initial val[] of all valinfo items
#define	MAXNAME		96			// longest name
#define	MAXVAL		256			// longest string value
#define	MAXPNAME	32			// longest process name

unsigned int	Pass	= 0;
bool	Pass_printed	= false;	// has this pass caused any output?
int	Update_interval	= 10;		// seconds between updates
bool	Verbose		= false;
bool	Timewatch	= false;	// watch accumulated time
bool	Memwatch	= false;	// watch memory related items
bool	Procwatch	= false;	// watch process create/exit related items
bool	Filewatch	= false;	// watch file open/close related items
bool	Kernelwatch	= false;	// watch kernel related items
bool	Yaffswatch	= false;	// watch YAFFS related items
bool	Externaltrigger	= false;	// trigger new pass by watching for file?

typedef struct val{
	struct val	*vnext;
	struct val	*vprev;
	char		name[MAXNAME];
	char		val[MAXVAL];
	unsigned int	lastupdate;
	long long int	valint;
} val_t;
val_t *Vfree = NULL;

typedef struct proc {
	struct proc	*pnext;
	struct proc	*pprev;
	unsigned int	pid;		// pid of this process
	val_t		vlist;		// list of watched values
	unsigned int	vcount;		// how many values for this proc
	unsigned int	appeared;	// first time this pid was noticed
	unsigned int	lastupdate;	// last time this pid was updated
	bool		isclone;	// is this a clone of some other pid?
}proc_t;

proc_t *Pfree = NULL;
proc_t Phead = {
	.pnext = &Phead,
	.pprev = &Phead,
	.pid = -1,
	.vcount = 0,
	.appeared = -1,
	.lastupdate = -1,
	.isclone = false,
	};

// replace all whitespace with _
static inline void
no_white(char *s)
{
	for(; *s; s++)
		if( isspace(*s) )
			*s = '_';
}

static inline val_t *
val_alloc(void)
{
	val_t *v = Vfree;

	if( v == NULL ){
		v = (val_t *)malloc(sizeof(*v));
		if( v==NULL ){
			printf("Out of memory\n");
			exit(1);
			}
		}
	else
		Vfree = v->vnext;
	v->name[0] = '\0';
	v->val[0] = '\0';
	v->vnext = v;
	v->vprev = v;
	v->lastupdate = -1;
	return v;
}

// remove val from list and release it
static inline void
val_free(val_t *v)
{
	v->vnext->vprev = v->vprev;
	v->vprev->vnext = v->vnext;
	v->vnext = Vfree;
	Vfree = v;
}

// lookup value by name
// return existing value if found, otherwise create a new val_t with 'undefined' values
static inline val_t *
val_lookup(proc_t *p, const char *name)
{
	val_t *v;

	if( strcmp(name,"Name")==0 )
		return &p->vlist;
	for(v=p->vlist.vnext; v != &p->vlist; v=v->vnext)
		if( strncmp(name,v->name,MAXVAL-1)== 0)
			return v;
	// create it
	v = val_alloc();
	strncpy(v->name,name,MAXNAME-1);
	v->val[0] = '\0';
	v->valint = 0;
	v->vnext = p->vlist.vnext;
	v->vprev = &p->vlist;
	v->vnext->vprev = v;
	v->vprev->vnext = v;
	p->vcount++;
	return v;
}

static inline proc_t *
proc_alloc(void)
{
	proc_t *p = Pfree;
	val_t *v;

	if( p == NULL ){
		p = (proc_t *)malloc(sizeof(*p));
		if( p==NULL ){
			printf("Out of memory\n");
			exit(1);
			}
		}
	else
		Pfree = p->pnext;

	p->pid = -1;
	p->pnext = p;
	p->pprev = p;
	v = &p->vlist;
	v->vnext = v;
	v->vprev = v;
	strcpy(v->name,"Name");
	v->val[0] = '\0';
	p->vcount = 0;
	p->appeared = p->lastupdate = Pass;
	p->isclone = false;	// not a clone until proven otherwise
	return p;
}

static inline void
show_pass()
{
	time_t t;

	if( !Pass_printed ){
		time(&t);
		printf("=== Pass %d =================== %s",Pass,ctime(&t));
		Pass_printed=true;
		}
}

static inline char *
proc_name(proc_t *p)
{
	return val_lookup(p,"Name")->val;
}

static inline void
pid_display(proc_t *p)
{
	show_pass();
	printf("%d %s ",p->pid,proc_name(p));
}

static inline void
proc_free(proc_t *p)
{
	// remove from proc list
	p->pnext->pprev = p->pprev;
	p->pprev->pnext = p->pnext;

	// report if requested
	if(Procwatch && Verbose){
		pid_display(p);
		printf("================================================================Exited\n");
		}

	// save for later
	p->pnext = Pfree;
	Pfree = p;
}

static inline void
val_update_common(proc_t *p, val_t *v, char *newval)
{
	unsigned int long long oldint,newint;
	char *endo, *endn;
	char *oldval = v->val;

	if( *oldval == '\0' ){
		oldval = UNDEF;
		if( strcmp(v->name,"Name")==0 )	// name going from UNDEF to something, update it now so pid_display is right
			strncpy(v->val,newval,sizeof(v->val)-1);
		}
	if( *newval == '\0' )
		newval = UNDEF;

	pid_display(p);
	printf("%s %s %s",v->name,oldval,newval);
	strncpy(v->val,newval,sizeof(v->val)-1);
}

static inline void
val_update_str(proc_t *p, const char *name, char *newval)
{
	val_t *v = val_lookup(p,name);

	v->lastupdate = Pass;
	no_white(newval);
	if( v->val[0] == '\0' ){	// previously undefined
		if(Verbose || (p->lastupdate == p->appeared)){
			val_update_common(p,v,newval);
			printf("\n");
			}
		}
	else {	// see if it has changed
		if( strncmp(newval,v->val,MAXVAL-1) != 0 ){
			val_update_common(p,v,newval);
			printf("\n");
			}
		}
}

static inline void
val_update_int(proc_t *p, const char *name, const long long int val)
{
	val_t *v = val_lookup(p,name);
	char	newval[MAXVAL];

	v->lastupdate = Pass;
	sprintf(newval,"%llx",val);
	if( v->val[0] == '\0' ){	// previously undefined
		if(Verbose || (p->lastupdate == p->appeared)){
			val_update_common(p,v,newval);
			printf("\n");
			}
		v->valint = val;
		return;
		}

	if( v->valint == val )
		return;	// did not change

	val_update_common(p,v,newval);
	if( val > v->valint )
		printf(" +%llx\n",val-v->valint);
	else
		printf(" -%llx\n",v->valint-val);
	v->valint = val;
}

static inline proc_t *
lookup_proc(const int pid)
{
	proc_t *p;

	for(p=Phead.pnext; p != &Phead; p=p->pnext)
		if( p->pid == pid )
			break;
	if( p == &Phead ){
		p = proc_alloc();
		p->pid = pid;
		p->pnext = &Phead;
		p->pprev = Phead.pprev;
		p->pnext->pprev = p;
		p->pprev->pnext = p;
		if(Procwatch && Verbose){
			pid_display(p);
			printf("=================================================New\n");
			}
		}
	p->lastupdate = Pass;
	return p;
}

void
update_pid_status(proc_t *p, const char *path)
{
	FILE *fp = fopen(path,"r");
	char buf[BUFSIZE];
	char *s;
	int namelen;

	if(fp==NULL)return;
	while( fgets(buf,sizeof(buf),fp) != NULL ){
		if( strncmp("Name:",buf,5)==0 ){
			s = &buf[6];
			namelen = strlen(s);	// name length, including newline
			if( namelen > 0 )
				namelen--;
			s[namelen]='\0';
			no_white(s);
			val_update_str(p,"Name",s);
			}
		else if( Procwatch && Verbose && strncmp("State:",buf,6)==0 ){
			s = &buf[7];
			s[1] = '\0';
			val_update_str(p,"State",s);
			}
		else if( Procwatch && strncmp("Uid:",buf,4)==0 )
			val_update_int(p,"Uid",strtol(buf+4,NULL,10));
		else if( Procwatch && strncmp("PPid:",buf,5)==0 )
			val_update_int(p,"PPid",strtol(buf+5,NULL,10));
		else if( Memwatch && strncmp("VmSize:",buf,7)==0 )
			val_update_int(p,"VmSize",strtol(buf+7,NULL,10));
		else if( Memwatch && strncmp("VmPeak:",buf,7)==0 )
			val_update_int(p,"VmPeak",strtol(buf+7,NULL,10));
		else if( Memwatch && strncmp("VmLck:",buf,6)==0 )
			val_update_int(p,"VmLck",strtol(buf+6,NULL,10));
		else if( Memwatch && strncmp("VmRSS:",buf,6)==0 )
			val_update_int(p,"VmRSS",strtol(buf+6,NULL,10));
		else if( Memwatch && Verbose && strncmp("VmHWM:",buf,6)==0 )
			val_update_int(p,"VmHWM",strtol(buf+6,NULL,10));
		else if( Memwatch && strncmp("VmData:",buf,7)==0 )
			val_update_int(p,"VmData",strtol(buf+7,NULL,10));
		else if( Memwatch && strncmp("VmStk:",buf,6)==0 )
			val_update_int(p,"VmStk",strtol(buf+6,NULL,10));
		else if( Memwatch && strncmp("VmExe:",buf,6)==0 )
			val_update_int(p,"VmExe",strtol(buf+6,NULL,10));
		else if( Memwatch && strncmp("VmLib:",buf,6)==0 )
			val_update_int(p,"VmLib",strtol(buf+6,NULL,10));
		else if( Procwatch && strncmp("Threads:",buf,8)==0 )
			val_update_int(p,"Threads",strtol(buf+8,NULL,10));
		}
	fclose(fp);
}

void
update_pid_stat(proc_t *p, const char *path)
{
	FILE *fp = fopen(path,"r");
	char buf[BUFSIZE];
	int nscan;
	char task_comm[BUFSIZE];
	char state;
	int task_pid, ppid, task_pgrp, task_session;
	int tty_nr, tty_pgrp;
	unsigned long long int task_flags;
	unsigned long long int min_flt, cmin_flt, maj_flt, cmaj_flt;
	unsigned long long int tms_utime, tms_stime, tms_cutime, tms_cstime;
	unsigned long long int priority, nice, junk, it_real_value, start_time;
	unsigned long long int vsize, rss, rss_rlimit;
	unsigned long long int start_code, end_code, start_stack, esp, eip;
	unsigned long long int sigpending, sigblocked, sigignored, sigcaught;
	unsigned long long int wchan, task_nswap, task_cnswap;
	int exit_signal, processor;
	char *scanfmt = 
		"%d %s %c %d %d %d "
		"%d %d %llu "
		"%llu %llu %llu %llu "
		"%llu %llu %lld %lld "
		"%lld %lld %lld %lld %llu "
		"%llu %lld %llu "
		"%llu %llu %llu %llu %llu "
		"%llu %llu %llu %llu "
		"%llu %llu %llu %d %d\n"
		;
	char *s;

	if(fp==NULL)return;
	buf[0] = '\0';
	fgets(buf,sizeof(buf),fp);
	fclose(fp);
	if(buf[0]=='\0')
		return;

	// replace any whitespace betweeen () with _
	for( s = index(buf,'('); s && *s && *s != ')'; s++)
		if( isspace(*s) )
			*s = '_';

	nscan = sscanf(buf,scanfmt,
		&task_pid, task_comm, &state, &ppid, &task_pgrp, &task_session,
		&tty_nr, &tty_pgrp, &task_flags,
		&min_flt, &cmin_flt, &maj_flt, &cmaj_flt,
		&tms_utime, &tms_stime, &tms_cutime, &tms_cstime,
		&priority, &nice, &junk, &it_real_value, &start_time,
		&vsize, &rss, &rss_rlimit,
		&start_code, &end_code, &start_stack, &esp, &eip,
		&sigpending, &sigblocked, &sigignored, &sigcaught,
		&wchan, &task_nswap, &task_cnswap, &exit_signal, &processor);

	if( nscan != 39 ){
		printf("pid_stat nscan:%d\nbuf:%s\nscanfmt:%s\n",nscan,buf,scanfmt);
		return;
		}
	if(Timewatch){
		val_update_int(p,"Utime",tms_utime);
		val_update_int(p,"Stime",tms_stime);
		val_update_int(p,"CUtime",tms_cutime);
		val_update_int(p,"CStime",tms_cstime);
	}
	if(Procwatch && Verbose){
		val_update_int(p,"Sp",esp);
		val_update_int(p,"Pc",eip);
		}
	if(Procwatch){
		val_update_int(p,"Priority",priority);
		val_update_int(p,"TaskFlags",task_flags);
		val_update_int(p,"Nice",nice);
		val_update_int(p,"Sigpending",sigpending);
		val_update_int(p,"Sigblocked",sigblocked);
		val_update_int(p,"Sigignored",sigignored);
		val_update_int(p,"Sigcaught",sigcaught);
		}
}

void
update_pid_statm(proc_t *p, const char *path)
{
	FILE *fp = fopen(path,"r");
	char buf[BUFSIZE];
	int nscan;
	long long int size,resident,share,trs,lrs,drs,dt;

	if(fp==NULL)return;
	buf[0] = '\0';
	fgets(buf,sizeof(buf),fp);
	fclose(fp);
	if(buf[0]=='\0')
		return;
		
	nscan = sscanf(buf,"%lld %lld %lld %lld %lld %lld %lld\n",
		&size, &resident, &share, &trs, &lrs, &drs, &dt);
	if(nscan != 7 ){
		printf("pid_statm scan? %d\n",nscan);
		return;
		}
	val_update_int(p,"TextRSS",trs);
	val_update_int(p,"LibRSS",lrs);
	val_update_int(p,"DataRSS",drs);
	val_update_int(p,"Dirty",dt);
}

void
update_pid_maps(proc_t *p, const char *path)
{
	FILE *fp = fopen(path,"r");
	char *dash;
	char *range_end;
	char buf[BUFSIZE];
	unsigned long long mstart;
	unsigned long long mend;
	char name[BUFSIZE];

	if(fp==NULL)return;
	while( fgets(buf,sizeof(buf),fp) != NULL ){
		dash = strchr(buf,'-');
		if( dash==NULL )
			continue;
		if( sscanf(buf,"%llx-%llx",&mstart,&mend) != 2 ){
			continue;
			}
		sprintf(name,"Mmap-%016llx",mstart);
		val_update_int(p,name,mend);
		}
	fclose(fp);
}

void
update_pid_fd(proc_t *p, const char *path)
{
	DIR	*d = opendir(path);
	struct dirent	*e;
	int	linklen;
	int	fd;
	char	link[BUFSIZE];
	char	buf[BUFSIZE];
	int	fd_count = 0;

	if(d==NULL)return;
	while( (e=readdir(d)) ){
		fd = strtol(e->d_name,NULL,10);
		sprintf(buf,"%s/%d",path,fd);
		linklen = readlink(buf,link,sizeof(link)-1);
		if( linklen > 0 ){
			link[linklen] = '\0';
			sprintf(buf,"Fd%d",fd);
			val_update_str(p,buf,link);
			fd_count++;
			}
		}
	closedir(d);
	val_update_int(p,"FdCount",fd_count);
}

void
val_cleanup(proc_t *p, val_t *v)
{
	val_update_str(p,v->name,"");
	val_free(v);
	p->vcount--;
}

void
proc_cleanup(proc_t *p)
{
	val_t	*v;

	while( (v=p->vlist.vnext) != &p->vlist )	// reclaim all valinfo structures
		val_free(v);
	proc_free(p);
}

// scan cache for anything that has disappeared
// this can be either values stored, or whole processes
void
cleanup(void)
{
	proc_t	*p,*p2;
	val_t	*v, *v2;

	for(p=Phead.pnext; p != &Phead; p=p->pnext)
		if( p->lastupdate != Pass ){	// not seen this pass
			p2 = p->pprev;	// resume scan at previous
			proc_cleanup(p);
			p = p2;
			}
		else if( !p->isclone){	// if not a clone, check if any values have disappeared
			for(v=p->vlist.vnext; v != &p->vlist; v=v->vnext)
				if( v->lastupdate != Pass ){
					v2 = v->vprev;	// resume scan at previous
					val_cleanup(p,v);
					v = v2;
					}
			}
}

// scan vlist, looking for an exact match for v
int
valmatch(val_t *v, val_t *list)
{
	val_t	*vscan;

	// don't insist on a match for these
	if( strcmp(v->name,"PPid")==0 || strcmp(v->name,"TaskFlags")==0 )
		return 1;
	for(vscan = list->vnext; vscan != list; vscan=vscan->vnext)
		if( strcmp(v->name,vscan->name)==0 )	// found the right name
			return strcmp(v->val,vscan->val)==0 ;
	return 0;
}

// scan proc list looking for clone threads
// if a clone is found, it is marked as such and future scans of it are skipped
void
clone_check(void)
{
	proc_t	*p1,*p2;
	val_t	*v;
	char	*n1;
	int	matchval, matchpercent;

	for(p1=Phead.pnext; p1 != &Phead; p1=p1->pnext){
		if( p1->isclone )
			continue;	// already known clone
		n1 = proc_name(p1);
		for(p2=p1->pnext; p2 != &Phead; p2=p2->pnext){
			if( p2->isclone )
				continue;	// already known clone
			if( p1->vcount != p2->vcount )
				continue;	// different value lists
			if( strcmp(n1,proc_name(p2)) != 0 )
				continue;	// different names
			matchval=0;
			for(v=p1->vlist.vnext; v != &p1->vlist; v=v->vnext)
				if( valmatch(v,&p2->vlist) )
					matchval++;
			matchpercent = p2->vcount ? (matchval*100)/p2->vcount : 0;
			if( matchpercent > 95 ){
				p2->isclone = true;
				if(Procwatch && Verbose){
					pid_display(p2);
					printf("%d%% clone of %d\n",matchpercent,p1->pid);
					}
				}
			}
		}
}

// Update all user values of the currently selected process
// Caller has already chdir'd to the process being updated
void
update_user(proc_t *p)
{
	update_pid_status(p,"status");
	update_pid_stat(p,"stat");
	if( Memwatch && Verbose){
		update_pid_statm(p,"statm");
		update_pid_maps(p,"maps");
		}
	if( Filewatch )
		update_pid_fd(p,"fd");
}

static void
usage(void)
{
	printf("Usage: hawk [-v] [-x] [-t] [-m] [-p] [-f] [-k] [-y]\n");
	printf(" -t watch time\n");
	printf(" -m watch memory\n");
	printf(" -p watch process\n");
	printf(" -f watch files\n");
	printf(" -k watch kernel activity\n");
	printf(" -y watch YAFFS activity (implies -k)\n");
	printf(" -v verbose\n");
	printf(" -x external trigger by file (%s)\n",TRIGGER_FILE);
	printf("Default is -m -f\n");
	exit(1);
}

static inline int
discard(FILE *fp, int nlines)
{
	char buf[BUFSIZE];

	while(nlines--){
		if( fgets(buf,sizeof(buf),fp) == NULL )
			return 0;
		}
	return 1;
}

void
update_system_slabinfo(proc_t *p, char *path)
{
	FILE *fp = fopen(path,"r");
	char buf[BUFSIZE];
	char slabname[BUFSIZE];
	char name[BUFSIZE];
	unsigned long long int active_objs;

	if(fp==NULL)return;
	if( !discard(fp,2) ){
		printf("system_slabinfo\n");	// skip version number
		fclose(fp);
		return;
		}
	while( fgets(buf,sizeof(buf),fp) != NULL ){
		sscanf(buf,"%s %llu", slabname,&active_objs);
		snprintf(name,sizeof(name),"SLAB-%s",slabname);
		val_update_int(p,name,active_objs);
		}
	fclose(fp);
}

void
update_system_meminfo(proc_t *p, char *path)
{
	FILE *fp = fopen(path,"r");
	char buf[BUFSIZE];
	char miname[BUFSIZE];
	char name[BUFSIZE];
	long long int mi;

	if(fp==NULL)return;
	if( !discard(fp,3) ){ // skip header, mem summary, swap summary
		printf("system_meminfo\n");
		fclose(fp);
		return;
		}

	while( fgets(buf,sizeof(buf),fp) != NULL ){
		sscanf(buf,"%s %lld",miname,&mi);
		miname[strlen(miname)-1]='\0';	// trim trailing :
		snprintf(name,sizeof(name),"MEM-%s",miname);
		val_update_int(p,name,mi);
		}
	fclose(fp);
}

void
update_system_vmstat(proc_t *p, char *path)
{
	FILE *fp = fopen(path,"r");
	char buf[BUFSIZE];
	char vmname[BUFSIZE];
	char name[BUFSIZE];
	long long int mi;

	if(fp==NULL)return;
	while( fgets(buf,sizeof(buf),fp) != NULL ){
		sscanf(buf,"%s %lld",vmname,&mi);
		snprintf(name,sizeof(name),"VM-%s",vmname);
		val_update_int(p,name,mi);
		}
	fclose(fp);
}

void
update_system_stat(proc_t *p, char *path)
{
	FILE *fp = fopen(path,"r");
	char buf[BUFSIZE];
	char name[BUFSIZE];
	long long int v;
	long long int t[10];

	if(fp==NULL)return;
	while( fgets(buf,sizeof(buf),fp) != NULL ){
		sscanf(buf,"%s %lld",name,&v);
		if( strcmp(name,"cpu")==0 ){
			// 2.6 kernel has 10 buckets for cpu ticks
			if( sscanf(buf,"%s %lld %lld %lld %lld %lld %lld %lld %lld %lld %lld",name,&t[0],&t[1],&t[2],&t[3],&t[4],&t[5],&t[6],&t[7],&t[8],&t[9]) == 11 ){
				val_update_int(p,"Tick-User",t[0]);
				val_update_int(p,"Tick-Nice",t[1]);
				val_update_int(p,"Tick-System",t[2]);
				val_update_int(p,"Tick-Idle",t[3]);
				val_update_int(p,"Tick-Wait",t[4]);
				val_update_int(p,"Tick-Irq",t[5]);
				val_update_int(p,"Tick-SoftIrq",t[6]);
				val_update_int(p,"Tick-Steal",t[7]);
				val_update_int(p,"Tick-RTUser",t[8]);
				val_update_int(p,"Tick-RTSystem",t[9]);
				}
			// 2.4 kernel has 4 buckets for cpu ticks
			else if( sscanf(buf,"%s %lld %lld %lld %lld",name,&t[0],&t[1],&t[2],&t[3]) == 5 ){
				val_update_int(p,"Tick-User",t[0]);
				val_update_int(p,"Tick-Nice",t[1]);
				val_update_int(p,"Tick-System",t[2]);
				val_update_int(p,"Tick-Idle",t[3]);
				}

			}
		else if( strcmp(name,"ctxt")==0 )
			val_update_int(p,"ContextSwitch",v);
		else if( strcmp(name,"processes")==0 )
			val_update_int(p,"Processes",v);
		else if( strcmp(name,"procs_running")==0 )
			val_update_int(p,"Running",v);
		else if( strcmp(name,"procs_blocked")==0 )
			val_update_int(p,"Blocked",v);
		}
	fclose(fp);
}

void
update_system_yaffs(proc_t *p, char *path)
{
	FILE *fp = fopen(path,"r");
	char buf[BUFSIZE];
	char device[BUFSIZE];
	char item[BUFSIZE];
	char tmp[BUFSIZE];
	int dnum;
	long long int val;
	char *s;

	if(fp==NULL)return;
	strcpy(device,"???");

	while( fgets(buf,sizeof(buf),fp) != NULL ){
		if( strncmp(buf,"Device ",7)==0 ){
			sscanf(buf,"%s %d \"%s\n",tmp,&dnum,device);
			device[strlen(device)-1]='\0';	// trim trailing "
			}
		else if( islower(buf[0]) ){
			sscanf(buf,"%s %lld",item,&val);
			for(s = &item[strlen(item)-1]; s>item && *s=='.'; s--)	// trim trailing ...
				*s = '\0';
			snprintf(tmp,sizeof(tmp),"YAFFS-%s-%s",device,item);
			val_update_int(p,tmp,val);
			}
		else
			{}	// ignore
		}
	fclose(fp);
}

void
update_system(void)
{
	proc_t *p = lookup_proc(0);

	val_update_str(p,"Name","KERNEL");
	if(Memwatch){
		update_system_slabinfo(p,"/proc/slabinfo");
		update_system_meminfo(p,"/proc/meminfo");
		update_system_vmstat(p,"/proc/vmstat");
		}
	if(Timewatch){
		update_system_stat(p,"/proc/stat");
		}
	if(Yaffswatch){
		update_system_yaffs(p,"/proc/yaffs");
		}
}

void
pause_for_next_pass(void)
{
	int fd;

	if( Externaltrigger ){
		while( (fd=open(TRIGGER_FILE,O_RDONLY,0)) < 0 )
			sleep(1);
		close(fd);
		unlink(TRIGGER_FILE);
		}
	else {
		sleep(Update_interval);
	}
}

static inline void
handle_args(char *s)
{
	if( isdigit(*s) ){
		Update_interval=atoi(s);
		return;
		}
	if( *s == '-' ){
		while( *s ){
			switch(*s++){
			case 'v': Verbose=true; break;
			case 't': Timewatch=true; break;
			case 'm': Memwatch=true; break;
			case 'p': Procwatch=true; break;
			case 'f': Filewatch=true; break;
			case 'k': Kernelwatch=true; break;
			case 'y': Yaffswatch=Kernelwatch=true; break;
			case 'x': Externaltrigger=true; break;
			case '-': break;
			default: usage(); break;
				}
			}
		return;
		}
	usage();
}

int
main(int argc, char **argv)
{
	int pid;
	DIR *d;
	struct dirent *v;
	int hawk_pid = getpid();
	proc_t *p;
	char pdir[BUFSIZE];

	while(--argc)
		handle_args(*++argv);

	if(Timewatch==0 && Memwatch==0 && Procwatch==0 && Filewatch==0 && Kernelwatch==0 && Yaffswatch==0)
		Memwatch=Filewatch=1;	// default to -m -f
	setbuf(stdout,NULL);
	if( nice(10) < 0 )
		printf("not nice\n");

	for(Pass=0;;Pass++){
		Pass_printed = false;
		if(Kernelwatch)
			update_system();
		d = opendir("/proc");
		if( d != NULL ){
			while( (v=readdir(d)) ){
				// only look at process directories
				pid = strtol(v->d_name,NULL,10);
				if( pid <= 0 || pid == hawk_pid)
					continue;
				p = lookup_proc(pid);
				if( !p->isclone ){
					sprintf(pdir,"/proc/%d",p->pid);
					if( chdir(pdir) >= 0 )	// chdir may fail if process exited since readdir saw it
						update_user(p);
					}
				}
			closedir(d);
			}
		clone_check();
		cleanup();
		pause_for_next_pass();
		}
	exit(0);
}
