%global _plugindir2	%{_libdir}/sasl2

Summary: Cyrus SASL XOAUTH2 Plugin
Name: cyrus-sasl-xoauth2-idp
Version: 1.1.0
Release: 1%{?dist}
License: BSD
Group: Applications/Internet
URL: http://github.com/oss-tsukuba/cyrus-sasl-xoauth2-idp/
Source0: %{name}-%{version}.tar.gz
BuildRoot: %{_tmppath}/%{name}-%{version}-%{release}-root
BuildRequires: cyrus-sasl-devel, scitokens-cpp-devel
Requires: cyrus-sasl, cyrus-sasl-lib, scitokens-cpp

%description
Cyrus SASL XOAUTH2 Plugin

%prep
%setup -q

%build
./autogen.sh
%configure
make

%install
rm -rf $RPM_BUILD_ROOT
%make_install

%clean
rm -rf $RPM_BUILD_ROOT

%files
%defattr(-,root,root,-)
%{_plugindir2}/libxoauth2.a
%{_plugindir2}/libxoauth2.la
%{_plugindir2}/libxoauth2.so*

%changelog
* Fri Apr  8 2022 SODA Noriyuki <soda@sra.co.jp> 0.2-1
- Initial build.
