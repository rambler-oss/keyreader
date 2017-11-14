Name:           keyreader
Version:        0.3.6
Release:        1%{?dist}
Summary:        Rambler keyreader
License:        LGPL3+
URL:            https://github.com/rambler-oss/keyreader
Source0:        https://github.com/rambler-oss/%{name}/archive/v%{version}.tar.gz

BuildRequires:  golang >= 1.5
BuildRequires:	git

%if 0%{?fedora} >= 21
# pull in golang libraries by explicit import path, inside the meta golang()
BuildRequires:  golang(gopkg.in/yaml.v2)
BuildRequires:  golang(github.com/go-ldap/ldap)
%endif

%description

%prep
%setup -q -n %{name}-%{version}
%patch0 -p1 -b .oldgroups-compat
%patch1 -p1 -b .ignore-fullaccess

%build
mkdir -p ./_build/src/github.com/rambler-oss/keyreader
ln -s $(pwd) ./_build/src/github.com/rambler-oss/keyreader
%if 0%{?redhat} == 6 || 0%{?centos} == 6
git clone -b v2 https://github.com/go-yaml/yaml ./_build/src/gopkg.in/yaml.v2
git clone -b v2 https://github.com/go-ldap/ldap ./_build/src/gopkg.in/ldap.v2
git clone -b v1 https://github.com/go-asn1-ber/asn1-ber ./_build/src/gopkg.in/asn1-ber.v1
%endif

export GOPATH=$(pwd)/_build:%{gopath}
export CGO_ENABLED=1
%if 0%{?redhat} || 0%{?centos}
go get -d .
go build -compiler gc -ldflags "${LDFLAGS:-} -B 0x$(head -c20 /dev/urandom|od -An -tx1|tr -d ' \n')" -a -v -x
%else
%gobuild
%endif

%check
%gotest

%install
install -d %{buildroot}%{_datadir}/keyreader
install -p -m 0755 contrib/keyreader.conf.example %{buildroot}%{_datadir}/keyreader/keyreader.conf.example
install -d %{buildroot}%{_libexecdir}
install -p -m 0755 %{name}-%{version} %{buildroot}%{_libexecdir}/keyreader
install -d %{buildroot}%{_sysconfdir}/rambler

%files
%doc COPYING
%{_libexecdir}/keyreader
%{_datadir}/keyreader/keyreader.conf.example

%changelog
* Tue Feb 28 2017 Iavael <iavael@rambler-co.ru> - 0.3.6-1
- Handle SIGPIPE properly

* Fri Feb 17 2017 Iavael <iavael@rambler-co.ru> - 0.3.5-1
- Handle error on writing to stdout

* Fri Feb 17 2017 Iavael <iavael@rambler-co.ru> - 0.3.4-1
- Fix bug in group permissions check

* Tue Feb 7 2017 Iavael <iavael@rambler-co.ru> - 0.3.3-1
- Don't fail if syslog is unafailable
- Update deps

* Thu Jan 26 2017 Iavael <iavael@rambler-co.ru> - 0.3.2-1
- Refactor NSS-related code
- Ignore sigpipe if sshd closes pipe too early

* Tue Jan 17 2017 Iavael <iavael@rambler-co.ru> - 0.3.1-1
- Add support for previous config formats
- Update deps

* Wed Jan 11 2017 Iavael <iavael@rambler-co.ru> - 0.3-1
- Fix bug and add ServerName to tls configuration
- Update deps
- Reduce fmt usage
- Add option to pass only keys with 'from' restriction
- Add support for multiple hostnames on config

* Tue Nov 8 2016 Iavael <iavael@rambler-co.ru> - 0.2.1-1
- Use stdlib.h instead of malloc.h

* Tue Nov 01 2016 Iavael <iavael@rambler-co.ru> - 0.2-1
- Add config file and netgroups support

