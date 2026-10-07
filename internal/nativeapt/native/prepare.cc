// Debian 13 amd64 / APT 3.0.3 preparer. No pkgPackageManager/DoInstall,
// dpkg execution, shell, generic command dispatch or approval path exists here.
// This program is NOT run by source/fixture tests. Native acceptance is separate.
#include <apt-pkg/acquire.h>
#include <apt-pkg/acquire-item.h>
#include <apt-pkg/algorithms.h>
#include <apt-pkg/cachefile.h>
#include <apt-pkg/configuration.h>
#include <apt-pkg/error.h>
#include <apt-pkg/fileutl.h>
#include <apt-pkg/hashes.h>
#include <apt-pkg/init.h>
#include <apt-pkg/metaindex.h>
#include <apt-pkg/pkgrecords.h>
#include <apt-pkg/pkgsystem.h>
#include <apt-pkg/sourcelist.h>
#include <apt-pkg/update.h>
#include <apt-pkg/version.h>
#include <algorithm>
#include <cerrno>
#include <chrono>
#include <cstring>
#include <dirent.h>
#include <fcntl.h>
#include <iostream>
#include <map>
#include <memory>
#include <regex>
#include <set>
#include <sstream>
#include <stdexcept>
#include <string>
#include <sys/stat.h>
#include <sys/statvfs.h>
#include <sys/utsname.h>
#include <unistd.h>
#include <vector>
#include "config.generated.hpp"

namespace {
constexpr char Root[] = "/var/lib/tracebolt/package-updates/";
constexpr char Policy[] = "/etc/tracebolt/package-actions/";
constexpr unsigned long long MaxArchive = 1ULL << 30, MaxTotal = 2ULL << 30;
constexpr unsigned long long MaxIndex = 512ULL << 20;
struct Failure : std::runtime_error { using std::runtime_error::runtime_error; };
void need(bool v, char const *why) { if (!v) throw Failure(why); }
struct FD {
 int n=-1; explicit FD(int n=-1):n(n){} ~FD(){if(n>=0)close(n);}
 FD(FD const&)=delete; FD& operator=(FD const&)=delete;
 FD(FD&& o) noexcept:n(o.n){o.n=-1;}
};
bool digest(std::string const &v) { return std::regex_match(v,std::regex("[0-9a-f]{64}")); }
bool valid_id(std::string const &v) {return std::regex_match(v,std::regex("update_[0-9a-f]{32}"))&&v!="update_00000000000000000000000000000000";}
void stat_safe(int fd,bool directory) {
 struct stat s{}; need(fstat(fd,&s)==0,"protected_stat");
 need(s.st_uid==0&&(s.st_mode&0022)==0,"protected_owner_mode");
 need(directory?S_ISDIR(s.st_mode):S_ISREG(s.st_mode),"protected_type");
 if(!directory)need(s.st_nlink==1,"protected_hardlink");
}
FD open_safe(std::string const &p,bool directory=false) {
 need(!p.empty()&&p[0]=='/'&&p.back()!='/'&&p.find("//")==std::string::npos,"protected_path");
 FD at(open("/",O_RDONLY|O_DIRECTORY|O_CLOEXEC));need(at.n>=0,"protected_root");stat_safe(at.n,true);
 std::istringstream in(p.substr(1));std::string part;std::vector<std::string> parts;
 while(std::getline(in,part,'/')){need(part!="."&&part!=".."&&!part.empty(),"protected_component");parts.push_back(part);}
 for(size_t i=0;i<parts.size();++i){bool dir=i+1<parts.size()||directory;FD next(openat(at.n,parts[i].c_str(),O_RDONLY|O_CLOEXEC|O_NOFOLLOW|(dir?O_DIRECTORY:0)));need(next.n>=0,"protected_open");stat_safe(next.n,dir);std::swap(at.n,next.n);}
 return at;
}
std::string read_fd(int fd,unsigned long long maximum) {
 struct stat st{};need(fstat(fd,&st)==0&&st.st_size>=0&&static_cast<unsigned long long>(st.st_size)<=maximum,"file_size");
 std::string b;char buf[65536];ssize_t n;while((n=read(fd,buf,sizeof(buf)))>0){need(b.size()+n<=maximum,"read_limit");b.append(buf,n);}need(n==0,"read_failed");return b;
}
std::string read_safe(std::string const &p,unsigned long long limit=1<<20) {auto f=open_safe(p);return read_fd(f.n,limit);}
std::string sha(std::string const &b){Hashes h(Hashes::SHA256SUM);need(h.Add(b.data(),b.size()),"hash_failed");return "sha256:"+h.GetHashString(Hashes::SHA256SUM).HashValue();}
std::string file_sha(std::string const &p,unsigned long long limit,unsigned long long *size=nullptr) {
 auto f=open_safe(p);struct stat st{};need(fstat(f.n,&st)==0&&st.st_size>=0&&static_cast<unsigned long long>(st.st_size)<=limit,"hash_size");
 Hashes h(Hashes::SHA256SUM);need(h.AddFD(f.n,static_cast<unsigned long long>(st.st_size)),"file_hash_failed");if(size)*size=st.st_size;
 return "sha256:"+h.GetHashString(Hashes::SHA256SUM).HashValue();
}
std::vector<std::string> names(std::string const &p) {
 auto f=open_safe(p,true);DIR *d=fdopendir(dup(f.n));need(d!=nullptr,"directory_read");std::vector<std::string> out;
 while(auto e=readdir(d)){std::string n=e->d_name;if(n!="."&&n!="..")out.push_back(n);}closedir(d);std::sort(out.begin(),out.end());return out;
}
std::string parent(std::string const &p){return p.substr(0,p.rfind('/'));}
std::string base(std::string const &p){return p.substr(p.rfind('/')+1);}
void write_new(std::string const &p,std::string const &b) {
 auto d=open_safe(parent(p),true);FD f(openat(d.n,base(p).c_str(),O_WRONLY|O_CREAT|O_EXCL|O_CLOEXEC|O_NOFOLLOW,0600));need(f.n>=0,"create_only_file");
 size_t off=0;while(off<b.size()){ssize_t n=write(f.n,b.data()+off,b.size()-off);need(n>0,"write_failed");off+=n;}need(fsync(f.n)==0&&fsync(d.n)==0,"durability_failed");
}
void mkdir_new(std::string const &p) {auto d=open_safe(parent(p),true);need(mkdirat(d.n,base(p).c_str(),0700)==0,"create_only_directory");need(fsync(d.n)==0,"directory_sync");}
void replace_all(std::string &s,std::string const &from,std::string const &to){size_t n=0;while((n=s.find(from,n))!=std::string::npos){s.replace(n,from.size(),to);n+=to.size();}}
std::string config(std::string const &job,std::string const &id){std::string s=kConfigTemplate;replace_all(s,"$JOB",job);replace_all(s,"$ID",id);return s;}
std::string quote(std::string const &s){std::string o="\"";for(unsigned char c:s){need(c>=32&&c<127,"non_ascii_evidence");switch(c){case '\\':o+="\\\\";break;case '"':o+="\\\"";break;case '<':o+="\\u003c";break;case '>':o+="\\u003e";break;case '&':o+="\\u0026";break;default:o+=char(c);}}return o+'"';}
void optional_config(std::map<std::string,std::string>& files,std::string const &p){struct stat st{};if(lstat(p.c_str(),&st)!=0){need(errno==ENOENT,"config_stat");return;}files[p.substr(1)]=read_safe(p);}
void safe_dpkg_config(std::string const &raw) {
 std::istringstream in(raw);std::string line;
 while(std::getline(in,line)){
  auto first=line.find_first_not_of(" \t\r");
  if(first==std::string::npos||line[first]=='#')continue;
  auto last=line.find_last_not_of(" \t\r");line=line.substr(first,last-first+1);
  need(line=="no-debsig"||line=="log /var/log/dpkg.log","unsupported_dpkg_configuration");
 }
}
std::string host_config_digest(){
 std::map<std::string,std::string> files;
 for(auto const&p:{"/etc/apt/apt.conf","/etc/dpkg/dpkg.cfg"})optional_config(files,p);
 for(auto const&p:{"/etc/apt/apt.conf.d","/etc/dpkg/dpkg.cfg.d"}){struct stat st{};if(lstat(p,&st)!=0){need(errno==ENOENT,"config_dir_stat");continue;}for(auto const&n:names(p))optional_config(files,std::string(p)+"/"+n);}
 for(auto const&[n,v]:files)if(n.rfind("etc/dpkg/",0)==0)safe_dpkg_config(v);
 std::string b="Tracebolt excluded APT config v1";b+='\0';for(auto const&[n,v]:files){b+=n;b+='\0';b+=std::to_string(v.size());b+='\0';b+=v;b+='\0';}return sha(b);
}
std::vector<std::string> words(std::string const&s){std::istringstream in(s);std::vector<std::string>w;std::string v;while(in>>v)w.push_back(v);return w;}
void source_policy(std::string const &raw) {
 // First slice intentionally excludes source options, embedded keys, deb-src,
 // custom methods, trusted=yes and unsigned repositories. The one fixed copied
 // keyring is the only trust store. Sources are approved locally, never remotely.
 need(!raw.empty()&&raw.back()=='\n'&&raw.find('\r')==std::string::npos,"sources_framing");
 std::set<std::string> fields;unsigned stanzas=0;std::istringstream in(raw);std::string line;
 auto finish=[&](){if(fields.empty())return;for(auto k:{"Types","URIs","Suites","Components","Architectures"})need(fields.count(k)==1,"sources_required_field");fields.clear();need(++stanzas<=16,"sources_count");};
 while(std::getline(in,line)){if(line.empty()){finish();continue;}need(line[0]!=' '&&line[0]!='\t'&&line[0]!='#',"sources_unsupported_line");auto colon=line.find(": ");need(colon!=std::string::npos,"sources_field");auto key=line.substr(0,colon),v=line.substr(colon+2);need(fields.insert(key).second&&!v.empty(),"sources_duplicate");
 if(key=="Types")need(v=="deb","source_type");else if(key=="Architectures")need(v=="amd64","source_arch");
 else if(key=="URIs"){auto w=words(v);need(w.size()==1&&std::regex_match(v,std::regex("https://[A-Za-z0-9.-]+(/[A-Za-z0-9_./-]*)?")),"source_uri");}
 else if(key=="Suites"){auto w=words(v);need(w.size()==1&&(v=="trixie"||v=="trixie-updates"||v=="trixie-security"),"source_suite");}
 else if(key=="Components"){for(auto const&w:words(v))need(w=="main"||w=="contrib"||w=="non-free"||w=="non-free-firmware","source_component");}
 else throw Failure("sources_unknown_field");}
 finish();need(stanzas>0,"sources_empty");
}
std::string snapshot(std::string const &job){
 auto source=read_safe(std::string(Policy)+"sources.sources");source_policy(source);
 auto prefs=read_safe(std::string(Policy)+"preferences");auto key=read_safe(std::string(Policy)+"keyring.gpg",8<<20);need(!key.empty(),"keyring_empty");
 mkdir_new(job+"/snapshot");mkdir_new(job+"/snapshot/empty");write_new(job+"/snapshot/empty.conf","");write_new(job+"/snapshot/sources.sources",source);write_new(job+"/snapshot/preferences",prefs);write_new(job+"/snapshot/keyring.gpg",key);
 std::string b="Tracebolt APT source snapshot v1";b+='\0';for(auto const&v:{source,prefs,key}){b+=std::to_string(v.size());b+='\0';b+=v;b+='\0';}return sha(b);
}
struct BoundedProgress : pkgAcquireStatus {
 std::chrono::steady_clock::time_point end=std::chrono::steady_clock::now()+std::chrono::seconds(240);
 bool MediaChange(std::string,std::string)override{return false;}
 bool Pulse(pkgAcquire *a)override{pkgAcquireStatus::Pulse(a);return std::chrono::steady_clock::now()<end&&CurrentBytes<=MaxTotal&&TotalBytes<=MaxTotal;}
};
struct Selected {std::string name,arch;pkgCache::PkgIterator pkg;pkgCache::VerIterator oldv,newv;};
std::vector<std::pair<std::string,std::string>> selection(std::string const &job){auto raw=read_safe(job+"/selection.tsv",32768);need(!raw.empty()&&raw.back()=='\n',"selection_framing");std::istringstream in(raw);std::string line,last;std::vector<std::pair<std::string,std::string>>v;
 while(std::getline(in,line)){auto tab=line.find('\t');need(tab!=std::string::npos&&line.find('\t',tab+1)==std::string::npos,"selection_field");auto n=line.substr(0,tab),a=line.substr(tab+1);need(std::regex_match(n,std::regex("[a-z0-9][a-z0-9+.-]{1,255}"))&&a=="amd64"&&n>last,"selection_identity");last=n;v.emplace_back(n,a);need(v.size()<=32,"selection_limit");}return v;}
void clean_state(pkgCache &cache,pkgDepCache &dep){
 need(dep.BrokenCount()==0&&dep.PolicyBrokenCount()==0,"dpkg_dependency_state");
 for(auto p=cache.PkgBegin();!p.end();++p){need(p->InstState==pkgCache::State::Ok,"dpkg_error_state");need(p->CurrentState==pkgCache::State::NotInstalled||p->CurrentState==pkgCache::State::ConfigFiles||p->CurrentState==pkgCache::State::Installed,"dpkg_pending_state");}
 need(names("/var/lib/dpkg/updates").empty(),"dpkg_pending_updates");need(read_safe("/var/lib/dpkg/triggers/Unincorp").empty(),"dpkg_pending_triggers");
 auto dpkg=cache.FindPkg("dpkg","amd64");need(!dpkg.end()&&!dpkg.CurrentVer().end()&&std::string(dpkg.CurrentVer().VerStr()).rfind("1.22.",0)==0,"unsupported_dpkg_version");
}
std::string holds_digest(std::string const &raw) {
 std::map<std::string,std::string> fields;
 std::vector<std::string> rows;
 auto finish=[&](){
  auto state=words(fields["Status"]);
  if(!state.empty()&&state[0]=="hold"){
   need(state.size()==3&&std::regex_match(fields["Package"],std::regex("[a-z0-9][a-z0-9+.-]{1,255}"))&&std::regex_match(fields["Architecture"],std::regex("[a-z0-9][a-z0-9-]{0,63}")),"hold_record");
   rows.push_back(fields["Package"]+'\t'+fields["Architecture"]+'\n');
  }
  fields.clear();
 };
 std::istringstream in(raw);std::string line;
 while(std::getline(in,line)){
  if(line.empty()){finish();continue;}
  if(line[0]==' '||line[0]=='\t')continue;
  auto colon=line.find(": ");if(colon==std::string::npos)continue;
  auto key=line.substr(0,colon);
  if(key=="Status"||key=="Package"||key=="Architecture")need(fields.emplace(key,line.substr(colon+2)).second,"duplicate_status_field");
 }
 finish();std::sort(rows.begin(),rows.end());need(std::adjacent_find(rows.begin(),rows.end())==rows.end(),"duplicate_hold");
 std::string b;for(auto const&r:rows)b+=r;return sha(b);
}

std::string multitype(pkgCache::VerIterator const &v){std::string m=v.MultiArchType();if(m=="none")m="no";need(m=="no"||m=="same"||m=="foreign"||m=="allowed","unsupported_multiarch");return m;}
std::string version_json(pkgCache::VerIterator const &v,pkgRecords &records,bool installed){
 bool found=false,source=false;for(auto f=v.FileList();!f.end();++f){if(f.File().Flagged(pkgCache::Flag::NotSource)!=installed)continue;auto &r=records.Lookup(f);bool s=!r.RecordField("Source").empty();if(found)need(source==s,"ambiguous_source_mapping");found=true;source=s;}
 need(found,"missing_version_record");return "{\"version\":"+quote(v.VerStr())+",\"sourcePackage\":"+quote(v.SourcePkgName())+",\"sourceVersion\":"+quote(v.SourceVerStr())+",\"sourceMapping\":"+quote(source?"source-field":"binary-default")+",\"multiArch\":"+quote(multitype(v))+"}";
}
struct Provenance {std::string archive,filehash,sourcehash,releasehash,indexhash,indexpath,label,suite,component;unsigned long long size;};
Provenance provenance(pkgCache &cache,pkgSourceList &sources,pkgRecords &records,pkgCache::VerIterator const&v,std::string const&snapshot_hash,std::string const&job){
 pkgCache::VerFileIterator selected;unsigned count=0;for(auto f=v.FileList();!f.end();++f){if(f.File().Flagged(pkgCache::Flag::NotSource))continue;selected=f;++count;}need(count==1,"ambiguous_candidate_indexes");
 auto file=selected.File();auto &r=records.Lookup(selected);auto hs=r.Hashes();auto ah=hs.find("SHA256");need(ah&&digest(ah->HashValue()),"archive_sha256_missing");auto size=hs.FileSize();need(size>0&&size<=MaxArchive&&v->Size==size,"archive_size");auto filename=r.FileName();need(std::regex_match(filename,std::regex("[A-Za-z0-9_+.-]+(/[A-Za-z0-9_+.:~-]+)*\\.deb"))&&filename.find("..") == std::string::npos,"archive_filename");
 unsigned matched=0;Provenance out{filename,"sha256:"+ah->HashValue(),"","","","","","","",size};
 for(auto m:sources){for(auto const&t:m->GetIndexTargets()){
 if(t.Option(IndexTarget::EXISTING_FILENAME)!=file.FileName())continue;
 ++matched;
 need(!t.OptionBool(IndexTarget::ALLOW_INSECURE)&&!t.OptionBool(IndexTarget::ALLOW_WEAK)&&!t.OptionBool(IndexTarget::ALLOW_DOWNGRADE_TO_INSECURE),"insecure_index");
 need(m->IsTrusted()&&m->GetTrusted()!=metaIndex::TRI_YES,"untrusted_or_forced_source");auto rel=m->FindInCache(cache,false);need(!rel.end(),"release_cache_mapping");std::string releasefile=rel.FileName();need(releasefile.rfind(job+"/lists/",0)==0&&base(releasefile).find("InRelease")!=std::string::npos,"signed_inrelease_required");
 std::string why;need(m->Load(releasefile,&why),"release_parse");need(m->GetCodename()=="trixie"||m->GetCodename()=="trixie-updates"||m->GetCodename()=="trixie-security","release_codename");auto sum=m->Lookup(t.MetaKey);need(sum&&sum->Size>0&&sum->Size<=MaxIndex,"release_index_entry");auto ih=sum->Hashes.find("SHA256");need(ih&&digest(ih->HashValue()),"release_index_sha256");
 std::string indexfile=file.FileName();need(indexfile.rfind(job+"/lists/",0)==0,"private_index");unsigned long long indexsize;out.indexhash=file_sha(indexfile,MaxIndex,&indexsize);need(indexsize==sum->Size&&out.indexhash=="sha256:"+ih->HashValue(),"release_index_binding");out.releasehash=file_sha(releasefile,16<<20);out.indexpath=t.MetaKey;out.label=m->GetLabel();out.suite=m->GetSuite();out.component=t.Option(IndexTarget::COMPONENT);for(auto const&text:{out.label,out.suite,out.component}){need(!text.empty()&&text.size()<=128,"source_text_bounds");for(unsigned char c:text)need(c>=32&&c<127,"source_text_control");}
 need(std::regex_match(out.indexpath,std::regex("[A-Za-z0-9_+.-]+(/[A-Za-z0-9_+.-]+)*"))&&out.indexpath.find("..") == std::string::npos,"index_path");
 std::string b="Tracebolt APT source identity v1";b+='\0';for(auto const&x:{snapshot_hash,m->GetURI(),m->GetDist(),t.URI,t.MetaKey}){b+=x;b+='\0';}out.sourcehash=sha(b);
 }}need(matched==1,"ambiguous_release_index_mapping");return out;
}
std::string archive_json(Provenance const &p){return "{\"sha256\":"+quote(p.filehash)+",\"size\":"+std::to_string(p.size)+",\"filename\":"+quote(p.archive)+",\"sourceIdentityDigest\":"+quote(p.sourcehash)+",\"release\":\"debian-13-trixie\",\"releaseDigest\":"+quote(p.releasehash)+",\"indexDigest\":"+quote(p.indexhash)+",\"indexPath\":"+quote(p.indexpath)+",\"authentication\":\"native-apt-authenticated\"}";}
void prepare(std::string const &id){
 need(geteuid()==0&&getuid()==0,"root_required");need(valid_id(id),"invalid_job_id");auto job=std::string(Root)+id;auto jobfd=open_safe(job,true);auto wanted=selection(job);
 struct utsname u{};need(uname(&u)==0&&std::string(u.machine)=="x86_64","unsupported_architecture");auto os=read_safe("/usr/lib/os-release");need(os.find("\nID=debian\n")!=std::string::npos&&(os.find("\nVERSION_ID=\"13\"\n")!=std::string::npos||os.find("\nVERSION_ID=13\n")!=std::string::npos),"unsupported_os");
 need(std::string(pkgVersion)=="3.0.3","unsupported_apt_version");
 auto host=host_config_digest();auto opt=read_safe(std::string(Policy)+"native-opt-in",4096);
 need(opt=="tracebolt-reviewed-isolated-apt-config-debian13-amd64-v1\n"+host+"\n","local_opt_in_or_host_config_changed");
 auto cfg=read_safe(job+"/apt.conf");need(cfg==config(job,id),"unreviewed_apt_config");auto snapshot_hash=snapshot(job);
 mkdir_new(job+"/lists");mkdir_new(job+"/lists/partial");mkdir_new(job+"/archives");mkdir_new(job+"/archives/partial");mkdir_new(job+"/log");
 // The environment is replaced, never augmented. No inherited APT_CONFIG,
 // LD_PRELOAD, proxy/auth variables, shell functions or dpkg options survive.
 need(clearenv()==0,"clear_environment");for(auto const&[k,v]:std::map<std::string,std::string>{{"PATH","/usr/sbin:/usr/bin:/sbin:/bin"},{"LC_ALL","C"},{"LANG","C"},{"DEBIAN_FRONTEND","noninteractive"},{"APT_CONFIG",job+"/apt.conf"}})need(setenv(k.c_str(),v.c_str(),1)==0,"environment_set");
 need(pkgInitConfig(*_config)&&pkgInitSystem(*_config,_system),"apt_initialization");
 pkgSourceList sources;need(sources.ReadMainList(),"apt_sources");BoundedProgress progress;
 need(ListUpdate(progress,sources,100000)&&!_error->PendingError(),"authenticated_refresh_failed");auto refreshed=time(nullptr);
 // Native locks are held until this process exits. There is no disable-locking,
 // simulation, repair, lock-file deletion, competitor kill or dpkg execution.
 pkgCacheFile cf;need(cf.Open(nullptr,true)&&!_error->PendingError(),"apt_cache_or_lock");auto &cache=*cf.GetPkgCache();auto &dep=*cf.GetDepCache();auto &native_sources=*cf.GetSourceList();clean_state(cache,dep);
 auto status_before=read_safe("/var/lib/dpkg/status",64<<20);auto dpkg_before=sha(status_before);auto inventory_hash=dpkg_before,holds_hash=holds_digest(status_before);
 std::vector<Selected> selected;std::set<std::string> requested;
 for(auto const&[n,a]:wanted){auto p=cache.FindPkg(n,a);need(!p.end()&&p->CurrentState==pkgCache::State::Installed&&p->SelectedState!=pkgCache::State::Hold,"not_installed_or_held");auto old=p.CurrentVer(),candidate=dep.GetCandidateVersion(p);need(!old.end()&&!candidate.end()&&std::string(old.Arch())==a&&std::string(candidate.Arch())==a,"candidate_architecture");need(_system->VS->CmpVersion(old.VerStr(),candidate.VerStr())<0,"not_strict_upgrade");need(!dep.PhasingApplied(p),"phased_candidate");dep.SetCandidateVersion(candidate);dep.MarkProtected(p);selected.push_back({n,a,p,old,candidate});requested.insert(n+":"+a);}
 {pkgDepCache::ActionGroup group(dep);for(auto const&s:selected)need(dep.MarkInstall(s.pkg,true,0,true),"mark_install_failed");}
 pkgProblemResolver resolver(&dep);need(resolver.Resolve(false)&&!_error->PendingError(),"solver_failed");need(dep.BrokenCount()==0&&dep.PolicyBrokenCount()==0,"solver_broken");
 unsigned changes=0;for(auto p=cache.PkgBegin();!p.end();++p){auto const&s=dep[p];if(s.Keep()&&!s.ReInstall())continue;++changes;need(s.Install()&&s.Upgrade()&&!s.NewInstall()&&!s.Delete()&&!s.ReInstall()&&requested.count(std::string(p.Name())+":"+p.Arch())==1,"solver_extra_action");}
 unsigned long long installed_bytes=0;for(auto const&s:selected){need(s.newv->InstalledSize<=MaxTotal-installed_bytes,"installed_size_limit");installed_bytes+=s.newv->InstalledSize;}
 for(auto const&mount:{"/","/usr","/var","/boot"}){struct statvfs space{};need(statvfs(mount,&space)==0&&static_cast<unsigned long long>(space.f_bavail)*space.f_frsize>installed_bytes+(512ULL<<20),"insufficient_install_space");}
 need(changes==selected.size(),"solver_missing_action");for(auto const&s:selected)need(dep[s.pkg].InstVerIter(cache)==s.newv,"solver_changed_candidate");
 pkgRecords records(cache);std::vector<Provenance> proofs;unsigned long long total=0;for(auto const&s:selected){proofs.push_back(provenance(cache,native_sources,records,s.newv,snapshot_hash,job));total+=proofs.back().size;need(total<=MaxTotal,"archive_total_limit");}
 struct statvfs disk{};need(statvfs(job.c_str(),&disk)==0&&static_cast<unsigned long long>(disk.f_bavail)*disk.f_frsize>total+(128ULL<<20),"insufficient_staging_space");
 BoundedProgress downloads;pkgAcquire acquire(&downloads);std::vector<std::string> paths(selected.size());std::vector<pkgAcqArchive*> items;for(size_t i=0;i<selected.size();++i)items.push_back(new pkgAcqArchive(&acquire,&native_sources,&records,selected[i].newv,paths[i]));
 need(acquire.Run(100000)==pkgAcquire::Continue&&!_error->PendingError(),"archive_download_failed");std::set<std::string> used;
 std::string packages="[",archives="[";
 for(size_t i=0;i<selected.size();++i){auto const&s=selected[i];auto const&p=proofs[i];need(items[i]->Status==pkgAcquire::Item::StatDone&&items[i]->Complete&&items[i]->IsTrusted(),"archive_authentication_failed");need(parent(paths[i])==job+"/archives"&&used.insert(paths[i]).second,"archive_path");unsigned long long size;need(file_sha(paths[i],MaxArchive,&size)==p.filehash&&size==p.size,"archive_bytes_changed");
 if(i){packages+=',';archives+=',';}packages+="{\"name\":"+quote(s.name)+",\"architecture\":"+quote(s.arch)+",\"installState\":\"installed\",\"holdState\":\"unheld\",\"from\":"+version_json(s.oldv,records,true)+",\"to\":"+version_json(s.newv,records,false)+",\"archive\":"+archive_json(p)+"}";
 archives+="{\"path\":"+quote(paths[i])+",\"sha256\":"+quote(p.filehash)+",\"size\":"+std::to_string(p.size)+"}";}
 packages+=']';archives+=']';std::map<std::string,Provenance> unique_sources;for(auto const&p:proofs)unique_sources.emplace(p.sourcehash,p);std::string source_json="[";for(auto const&[hash,p]:unique_sources){if(source_json.size()>1)source_json+=',';source_json+="{\"identityDigest\":"+quote(hash)+",\"label\":"+quote(p.label)+",\"suite\":"+quote(p.suite)+",\"component\":"+quote(p.component)+"}";}source_json+=']';clean_state(cache,dep);need(file_sha("/var/lib/dpkg/status",64<<20)==dpkg_before&&host_config_digest()==host,"state_changed_during_preparation");auto inventory_at=time(nullptr);need(inventory_at>=refreshed&&inventory_at-refreshed<=300,"preparation_too_old");
 auto result="{\"version\":\"tracebolt.native-apt-prepared.v1\",\"updateId\":"+quote(id)+",\"aptVersion\":\"3.0.3\",\"metadataRefreshedAt\":"+std::to_string(refreshed)+",\"inventoryAt\":"+std::to_string(inventory_at)+",\"inventoryDigest\":"+quote(inventory_hash)+",\"dpkgStateDigest\":"+quote(dpkg_before)+",\"holdsDigest\":"+quote(holds_hash)+",\"sourceSnapshotDigest\":"+quote(snapshot_hash)+",\"hostConfigDigest\":"+quote(host)+",\"aptConfigDigest\":"+quote(sha(cfg))+",\"packages\":"+packages+",\"sources\":"+source_json+",\"archives\":"+archives+"}";
 need(result.size()<=256*1024,"bundle_limit");write_new(job+"/prepared.json",result);
}
} // namespace
int main(int argc,char**argv){try{need(argc==2,"one_job_id_required");prepare(argv[1]);return 0;}catch(Failure const&e){std::cerr<<"native_apt_prepare_failed:"<<e.what()<<'\n';return 1;}catch(...){std::cerr<<"native_apt_prepare_failed:internal\n";return 1;}}
