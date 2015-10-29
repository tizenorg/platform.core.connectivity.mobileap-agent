Name:		mobileap-agent
Summary:	Mobile AP daemon for setting tethering environments
Version:	1.0.38
Release:	1
Group:		System/Network
License:	Apache-2.0
Source0:	%{name}-%{version}.tar.gz

%if "%{?tizen_profile_name}" == "tv"
ExcludeArch: %{arm} %ix86 x86_64
%endif

BuildRequires:	pkgconfig(dlog)
BuildRequires:	pkgconfig(gio-2.0)
BuildRequires:	pkgconfig(glib-2.0)
BuildRequires:	pkgconfig(gthread-2.0)
BuildRequires:	pkgconfig(deviced)
BuildRequires:	pkgconfig(vconf)
BuildRequires:	pkgconfig(notification)
BuildRequires:	pkgconfig(capi-network-connection)
BuildRequires:	pkgconfig(capi-network-bluetooth)
BuildRequires:	pkgconfig(syspopup-caller)
BuildRequires:	pkgconfig(bundle)
BuildRequires:	pkgconfig(appcore-common)
BuildRequires:	pkgconfig(capi-network-wifi-direct)
BuildRequires:	pkgconfig(capi-network-wifi)
BuildRequires:	pkgconfig(alarm-service)
BuildRequires:	pkgconfig(appsvc)
BuildRequires:	pkgconfig(libssl)
BuildRequires:	cmake
%if "%{?tizen_profile_name}" != "tv"
Requires(post):	bluetooth-agent
%endif
Requires:	iproute2
Requires:	iptables
Requires:	dnsmasq

%description
Mobile AP daemon for setting tethering environments

%prep
%setup -q


%build
export CFLAGS="$CFLAGS -DTIZEN_DEBUG_ENABLE"
export CXXFLAGS="$CXXFLAGS -DTIZEN_DEBUG_ENABLE"
export FFLAGS="$FFLAGS -DTIZEN_DEBUG_ENABLE"

%cmake -DCMAKE_BUILD_TYPE="" \
%if "%{?tizen_profile_name}" == "tv"
	-DTIZEN_TV=1 \
%endif
%if "%{?tizen_target_name}" == "Z300H"
	-DTIZEN_WLAN_BOARD_SPRD=1 \
%endif
	.

make %{?jobs:-j%jobs}


%install
%make_install
mkdir -p %{buildroot}%{_sysconfdir}/dbus-1/system.d
cp mobileap-agent.conf %{buildroot}%{_sysconfdir}/dbus-1/system.d/mobileap-agent.conf

%post
/bin/chmod +x /opt/etc/dump.d/module.d/tethering_dump.sh

%files
%manifest mobileap-agent.manifest
%defattr(-,root,root,-)
/usr/share/dbus-1/system-services/org.tizen.tethering.service
%attr(644,root,root) %{_sysconfdir}/dbus-1/system.d/mobileap-agent.conf

%{_bindir}/mobileap-agent
/opt/etc/dump.d/module.d/tethering_dump.sh

