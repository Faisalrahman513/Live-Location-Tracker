// App.jsx - COMPLETE INTEGRATED VERSION
import React, { useState, useEffect } from 'react';
import { MapContainer, TileLayer, Marker, Popup, Polygon, useMapEvents } from 'react-leaflet';
import L from 'leaflet';
import 'leaflet/dist/leaflet.css';
import { 
    Map as MapIcon, Globe, Mail, ScanLine, MousePointer2, Target, Wifi, WifiOff, 
    Copy, Users, MapPin, AlertCircle, Shield, ExternalLink, AlertTriangle, 
    CheckCircle, User, Calendar, Database, Lock, Eye, Building, Hash, Fingerprint
} from 'lucide-react';

// Fix Leaflet marker icons
delete L.Icon.Default. prototype._getIconUrl;
L.Icon.Default.mergeOptions({
    iconRetinaUrl: 'https://cdnjs.cloudflare.com/ajax/libs/leaflet/1.9.4/images/marker-icon-2x.png',
    iconUrl: 'https://cdnjs.cloudflare.com/ajax/libs/leaflet/1.9.4/images/marker-icon.png',
    shadowUrl: 'https://cdnjs.cloudflare.com/ajax/libs/leaflet/1.9.4/images/marker-shadow.png',
});

// Custom Marker Creator
const createIcon = (color) => new L.DivIcon({
    className: 'custom-marker',
    html: `<div style="background: ${color};width: 18px;height: 18px;border-radius: 50%;border: 3px solid white;box-shadow:0 2px 6px rgba(0,0,0,0.3);"></div>`,
    iconSize: [18, 18],
    iconAnchor: [9, 9],
});

const icons = {
    locked: createIcon('#16a34a'),
    ip_only: createIcon('#ea580c'),
    vpn: createIcon('#dc2626'),
    breached: createIcon('#dc2626'),
    default: createIcon('#2563eb'),
};

const API = 'http://localhost:5000';

const parseJSON = (str) => {
    if (!str) return null;
    try { return JSON.parse(str); } catch { return null; }
};

const formatNumber = (num) => {
    if (! num) return '0';
    if (num >= 1000000000) return (num / 1000000000).toFixed(1) + 'B';
    if (num >= 1000000) return (num / 1000000).toFixed(1) + 'M';
    if (num >= 1000) return (num / 1000).toFixed(1) + 'K';
    return num.toString();
};

const SeverityBadge = ({ severity }) => {
    const colors = {
        'CRITICAL': { bg: '#fef2f2', color: '#dc2626', border: '#fecaca' },
        'HIGH': { bg: '#fff7ed', color: '#ea580c', border: '#fed7aa' },
        'MEDIUM': { bg: '#fefce8', color: '#ca8a04', border: '#fef08a' },
        'LOW':  { bg: '#f0fdf4', color: '#16a34a', border: '#bbf7d0' },
        'NONE': { bg: '#f8fafc', color: '#64748b', border: '#e2e8f0' },
    };
    const style = colors[severity] || colors['NONE'];
    return (
        <span style={{ background: style.bg, color: style.color, border: `1px solid ${style.border}`, padding: '2px 8px', borderRadius: '4px', fontSize: '10px', fontWeight: 600 }}>
            {severity}
        </span>
    );
};

export default function App() {
    const [view, setView] = useState('MAP');
    const [targets, setTargets] = useState([]);
    const [input, setInput] = useState('');
    const [selectedId, setSelectedId] = useState(null);
    const [fence, setFence] = useState([]);
    const [isDrawing, setIsDrawing] = useState(false);
    const [fenceResult, setFenceResult] = useState(null);
    const [scanning, setScanning] = useState(false);
    const [expandedSections, setExpandedSections] = useState({
        breaches: true,
        accounts: true,
        device: false,
        location: true,
        security: true
    });

    const selectedTarget = targets.find(t => t.id === selectedId);
    const breachDetails = selectedTarget ?  parseJSON(selectedTarget.breach_details) : null;
    const linkedAccountsDetails = selectedTarget ? parseJSON(selectedTarget.linked_accounts_details) : null;
    const gravatarProfile = selectedTarget ? parseJSON(selectedTarget.gravatar_profile) : null;

    useEffect(() => {
        loadTargets();
        const interval = setInterval(loadTargets, 3000);
        return () => clearInterval(interval);
    }, []);

    const loadTargets = async () => {
        try {
            const res = await fetch(`${API}/api/targets`);
            if (res.ok) setTargets(await res.json());
        } catch (e) { console.error(e); }
    };

    const startScan = async (mode) => {
        if (! input.trim()) return alert('Enter a target');
        setScanning(true);
        try {
            await fetch(`${API}/api/scan`, {
                method: 'POST',
                headers: { 'Content-Type': 'application/json' },
                body: JSON.stringify({ query: input. trim(), mode })
            });
            setInput('');
            loadTargets();
        } catch (e) { alert('Error:  ' + e.message); }
        setScanning(false);
    };

    const checkGeofence = async (target) => {
        if (fence.length < 3) return setFenceResult({ error: 'Draw at least 3 points' });
        if (!target.lat || !target. lon) return setFenceResult({ error: 'No GPS coordinates' });
        try {
            const res = await fetch(`${API}/api/geofence_calc`, {
                method: 'POST',
                headers: { 'Content-Type': 'application/json' },
                body:  JSON.stringify({ lat: target.lat, lon: target.lon, polygon: fence })
            });
            setFenceResult(await res.json());
        } catch (e) { setFenceResult({ error: e.message }); }
    };

    const copyLink = (name) => {
        navigator.clipboard.writeText(`${API}/meet/secure/${name}`);
        alert('Trap link copied! ');
    };

    const toggleSection = (section) => {
        setExpandedSections(prev => ({ ...prev, [section]: !prev[section] }));
    };

    const getIcon = (t) => {
        if (t.is_vpn) return icons.vpn;
        if (t.breach_count > 0) return icons.breached;
        if (t. status && t.status.includes('LOCKED')) return icons.locked;
        if (t.ip && ! t.lat) return icons.ip_only;
        return icons.default;
    };

    const getStatusColor = (status) => {
        if (!status) return '#6b7280';
        if (status.includes('LOCKED')) return '#16a34a';
        if (status.includes('CAPTURED')) return '#ea580c';
        if (status.includes('FOUND')) return '#2563eb';
        if (status.includes('VALID')) return '#16a34a';
        if (status.includes('BREACHED')) return '#dc2626';
        if (status.includes('FAKE') || status.includes('ERROR') || status.includes('DENIED')) return '#dc2626';
        return '#6b7280';
    };

    const getStatusBg = (status) => {
        if (!status) return '#f3f4f6';
        if (status.includes('LOCKED')) return '#dcfce7';
        if (status.includes('CAPTURED')) return '#ffedd5';
        if (status.includes('FOUND')) return '#dbeafe';
        if (status.includes('VALID')) return '#dcfce7';
        if (status.includes('BREACHED')) return '#fee2e2';
        if (status.includes('FAKE') || status.includes('ERROR') || status.includes('DENIED')) return '#fee2e2';
        return '#f3f4f6';
    };

    const MapEvents = () => {
        useMapEvents({
            click(e) {
                if (isDrawing) setFence([...fence, [e.latlng.lat, e.latlng.lng]]);
            }
        });
        return null;
    };

    const SectionHeader = ({ title, icon:  Icon, section, count, color = '#64748b' }) => (
        <div onClick={() => toggleSection(section)} style={{ display: 'flex', alignItems:  'center', justifyContent: 'space-between', cursor: 'pointer', padding: '10px 0', borderBottom: expandedSections[section] ? '1px solid #e2e8f0' : 'none', marginBottom: expandedSections[section] ? '12px' : '0' }}>
            <div style={{ display: 'flex', alignItems: 'center', gap: '8px' }}>
                <Icon size={16} color={color} />
                <span style={{ color: '#1e293b', fontSize: '13px', fontWeight: 600 }}>{title}</span>
                {count !== undefined && <span style={{ background: '#e2e8f0', color:  '#475569', padding: '2px 8px', borderRadius: '10px', fontSize: '11px', fontWeight: 600 }}>{count}</span>}
            </div>
            <span style={{ color: '#94a3b8', fontSize: '18px', transform: expandedSections[section] ? 'rotate(180deg)' : 'rotate(0deg)', transition: 'transform 0.2s' }}>▼</span>
        </div>
    );

    return (
        <div style={{ display: 'flex', height: '100vh', width: '100vw', fontFamily: '-apple-system, BlinkMacSystemFont, "Segoe UI", Roboto, "Helvetica Neue", Arial, sans-serif', background: '#f8fafc', overflow: 'hidden' }}>
            {/* SIDEBAR */}
            <div style={{ width: '320px', minWidth: '320px', background: 'white', display: 'flex', flexDirection:  'column', borderRight: '1px solid #e2e8f0', boxShadow: '2px 0 8px rgba(0,0,0,0.05)' }}>
                {/* Header */}
                <div style={{ padding: '20px', borderBottom: '1px solid #e2e8f0', background: 'linear-gradient(135deg, #1e40af 0%, #3b82f6 100%)' }}>
                    <h1 style={{ color: 'white', fontSize: '18px', margin: 0, display: 'flex', alignItems:  'center', gap: '10px', fontWeight: 700 }}>
                        <Target size={22} /> LIVE LOCATION TRACKER
                    </h1>
                    <div style={{ color: 'rgba(255,255,255,0.8)', fontSize: '11px', marginTop: '4px', paddingLeft: '39px' }}>Industry Standard OSINT Platform v4.0</div>
                </div>

                {/* Nav */}
                <div style={{ padding: '15px', borderBottom: '1px solid #e2e8f0', display: 'flex', gap: '8px' }}>
                    <button onClick={() => setView('MAP')} style={{ flex: 1, padding: '10px 16px', background: view === 'MAP' ? '#2563eb' : '#f1f5f9', color: view === 'MAP' ? 'white' : '#475569', border: 'none', borderRadius: '8px', cursor: 'pointer', fontWeight: 600, fontSize: '13px', display: 'flex', alignItems:  'center', justifyContent: 'center', gap: '6px' }}>
                        <MapIcon size={16} /> Map
                    </button>
                    <button onClick={() => setView('SCAN')} style={{ flex: 1, padding: '10px 16px', background:  view === 'SCAN' ?  '#2563eb' : '#f1f5f9', color:  view === 'SCAN' ?  'white' : '#475569', border: 'none', borderRadius: '8px', cursor:  'pointer', fontWeight: 600, fontSize: '13px', display: 'flex', alignItems: 'center', justifyContent: 'center', gap: '6px' }}>
                        <ScanLine size={16} /> Scanner
                    </button>
                </div>

                {/* Geofence Controls */}
                {view === 'MAP' && (
                    <div style={{ padding: '15px', borderBottom: '1px solid #e2e8f0', background: '#fafbfc' }}>
                        <div style={{ color: '#64748b', fontSize: '10px', fontWeight: 700, marginBottom: '10px', letterSpacing: '0.5px' }}>GEOFENCE TOOLS (C++ DSA)</div>
                        <div style={{ display: 'flex', gap: '8px', marginBottom:  '10px' }}>
                            <button onClick={() => setIsDrawing(!isDrawing)} style={{ flex: 1, padding:  '8px 12px', background: isDrawing ?  '#dc2626' : 'white', color: isDrawing ? 'white' : '#374151', border: '1px solid ' + (isDrawing ? '#dc2626' : '#d1d5db'), borderRadius: '6px', cursor: 'pointer', fontSize: '12px', fontWeight: 500, display: 'flex', alignItems:  'center', justifyContent: 'center', gap: '4px' }}>
                                <MousePointer2 size={14} /> {isDrawing ? 'Stop Drawing' : 'Draw Zone'}
                            </button>
                            <button onClick={() => { setFence([]); setFenceResult(null); }} style={{ padding: '8px 12px', background: 'white', color: '#374151', border: '1px solid #d1d5db', borderRadius: '6px', cursor: 'pointer', fontSize: '12px', fontWeight: 500 }}>
                                Clear ({fence.length})
                            </button>
                        </div>
                        {fenceResult && (
                            <div style={{ padding: '12px', background: fenceResult.error ? '#fef2f2' : fenceResult.inside ? '#f0fdf4' : '#fef2f2', border: '1px solid ' + (fenceResult.error ? '#fecaca' : fenceResult.inside ? '#bbf7d0' : '#fecaca'), borderRadius: '8px', fontSize: '12px' }}>
                                <div style={{ fontWeight: 600, color: fenceResult.error ? '#dc2626' : fenceResult.inside ? '#16a34a' : '#dc2626' }}>
                                    {fenceResult.error || (fenceResult.inside ? '✓ TARGET INSIDE ZONE' : '⚠ TARGET OUTSIDE ZONE')}
                                </div>
                                {! fenceResult.error && <div style={{ marginTop: '6px', color: '#64748b', fontSize: '11px' }}>Area: {(fenceResult.area_sq_m || 0).toLocaleString()} m² · Distance: {(fenceResult.nearest_fence_m || 0).toLocaleString()} m</div>}
                            </div>
                        )}
                    </div>
                )}

                {/* Targets List */}
                <div style={{ flex: 1, overflow: 'auto', padding: '15px' }}>
                    <div style={{ color: '#64748b', fontSize:  '10px', fontWeight: 700, marginBottom: '12px', letterSpacing: '0.5px', display: 'flex', alignItems: 'center', gap: '5px' }}>
                        <Users size={12} /> TARGETS ({targets.length})
                    </div>
                    {targets. length === 0 && (
                        <div style={{ textAlign: 'center', padding: '30px 15px', color: '#94a3b8' }}>
                            <Target size={32} style={{ marginBottom: '10px', opacity: 0.5 }} />
                            <div style={{ fontSize: '13px' }}>No targets yet</div>
                            <div style={{ fontSize: '11px', marginTop: '4px' }}>Start a scan to add targets</div>
                        </div>
                    )}
                    {targets.map(t => (
                        <div key={t.id} onClick={() => { setSelectedId(t.id); setView('SCAN'); }} style={{ padding: '12px', marginBottom: '8px', background: selectedId === t.id ? '#eff6ff' : 'white', borderRadius: '10px', cursor: 'pointer', border: '1px solid ' + (selectedId === t.id ? '#bfdbfe' : '#e2e8f0') }}>
                            <div style={{ display: 'flex', justifyContent: 'space-between', alignItems: 'center' }}>
                                <span style={{ color: '#1e293b', fontWeight: 600, fontSize: '14px' }}>{t.name}</span>
                                <div style={{ display: 'flex', gap: '4px', flexWrap: 'wrap' }}>
                                    {t. breach_count > 0 && <span style={{ background: '#fee2e2', color: '#dc2626', padding: '2px 6px', borderRadius: '4px', fontSize: '9px', fontWeight: 600 }}>{t.breach_count} BREACH{t.breach_count > 1 ? 'ES' : ''}</span>}
                                    {t.is_vpn && <span style={{ background: '#fee2e2', color: '#dc2626', padding: '2px 6px', borderRadius: '4px', fontSize: '9px', fontWeight: 600 }}>VPN</span>}
                                    {t.is_localhost && ! t.is_vpn && <span style={{ background: '#fef3c7', color: '#d97706', padding: '2px 6px', borderRadius: '4px', fontSize: '9px', fontWeight: 600 }}>LOCAL</span>}
                                </div>
                            </div>
                            <div style={{ display: 'flex', alignItems: 'center', gap:  '6px', marginTop: '6px' }}>
                                <span style={{ background: getStatusBg(t.status), color: getStatusColor(t.status), padding: '2px 8px', borderRadius: '4px', fontSize: '10px', fontWeight: 600 }}>{t.status || 'Pending'}</span>
                            </div>
                            {t.real_email && <div style={{ color: '#2563eb', fontSize: '11px', marginTop: '6px', display: 'flex', alignItems: 'center', gap: '4px' }}><Mail size={10} /> {t.real_email}</div>}
                            {t.ip && ! t.real_email && <div style={{ color: '#64748b', fontSize: '11px', marginTop: '6px' }}>IP: {t.ip}</div>}
                        </div>
                    ))}
                </div>
            </div>

            {/* MAIN CONTENT */}
            <div style={{ flex: 1, display: 'flex', flexDirection:  'column', minWidth: 0 }}>
                {/* MAP VIEW */}
                {view === 'MAP' && (
                    <div style={{ flex: 1, position: 'relative', width: '100%', height: '100%' }}>
                        <MapContainer center={[33.68, 73.04]} zoom={11} style={{ position: 'absolute', top: 0, left: 0, right: 0, bottom: 0, width: '100%', height: '100%' }} scrollWheelZoom={true}>
                            <TileLayer url="https://{s}.tile.openstreetmap.org/{z}/{x}/{y}.png" attribution='&copy; <a href="https://www.openstreetmap.org/copyright">OpenStreetMap</a>' />
                            <MapEvents />
                            {fence.length > 0 && <Polygon positions={fence} pathOptions={{ color: isDrawing ? '#f59e0b' : '#dc2626', fillOpacity: 0.15, weight: 2 }} />}
                            {targets.filter(t => t.lat && t.lon).map(t => (
                                <Marker key={t.id} position={[t.lat, t.lon]} icon={getIcon(t)}>
                                    <Popup>
                                        <div style={{ minWidth: '250px', fontFamily: '-apple-system, BlinkMacSystemFont, "Segoe UI", Roboto, sans-serif' }}>
                                            <div style={{ fontWeight: 700, fontSize: '15px', color: '#1e293b', marginBottom: '10px' }}>{t.name}</div>
                                            {t.real_email && <div style={{ fontSize: '12px', color: '#2563eb', marginBottom: '8px', display: 'flex', alignItems: 'center', gap: '4px' }}><Mail size={12} /> {t.real_email}</div>}
                                            <div style={{ fontSize: '12px', color: '#475569', marginBottom: '4px' }}><strong>IP:</strong> {t.ip || 'N/A'}</div>
                                            <div style={{ fontSize: '12px', color: '#475569', marginBottom: '4px' }}><strong>Status:</strong> {t.status}</div>
                                            <div style={{ fontSize: '12px', color: '#475569', marginBottom: '4px' }}><strong>Coords:</strong> {t.lat?. toFixed(5)}, {t.lon?.toFixed(5)}</div>
                                            {t.city && t.country && <div style={{ fontSize: '12px', color: '#475569', marginBottom: '10px' }}><strong>Location:</strong> {t.city}, {t.country}</div>}
                                            {t.breach_count > 0 && <div style={{ background: '#fef2f2', padding: '8px', borderRadius: '6px', marginBottom: '8px', fontSize: '11px', color: '#dc2626', border: '1px solid #fecaca' }}><strong>⚠️ Found in {t.breach_count} breach(es)</strong></div>}
                                            {t.accuracy > 0 && <div style={{ background: '#f0fdf4', padding: '8px', borderRadius: '6px', marginBottom: '8px', fontSize: '11px', color:  '#166534', border: '1px solid #bbf7d0' }}><strong>GPS Accuracy: </strong> ±{Math.round(t.accuracy)}m</div>}
                                            {t.is_vpn && <div style={{ background:  '#fef2f2', padding: '8px', borderRadius:  '6px', marginBottom: '8px', fontSize: '11px', color: '#dc2626', border: '1px solid #fecaca' }}>🛡️ VPN/Proxy Detected ({t.vpn_confidence}% confidence)</div>}
                                            <button onClick={() => checkGeofence(t)} style={{ width: '100%', padding: '10px', background: '#2563eb', color: 'white', border: 'none', borderRadius: '6px', cursor: 'pointer', fontSize: '12px', fontWeight: 600 }}>Check Geofence (C++ Kernel)</button>
                                        </div>
                                    </Popup>
                                </Marker>
                            ))}
                        </MapContainer>
                    </div>
                )}
                
                {/* SCAN VIEW - Continues in Part 2 */}
                                {/* SCAN VIEW - COMPLETE */}
                {view === 'SCAN' && (
                    <div style={{ flex: 1, overflow: 'auto', padding: '30px', background: '#f8fafc' }}>
                        <div style={{ maxWidth: '1000px', margin: '0 auto' }}>
                            {/* Scanner Card */}
                            <div style={{ background: 'white', borderRadius: '16px', padding:  '25px', marginBottom: '25px', boxShadow: '0 1px 3px rgba(0,0,0,0.1)', border: '1px solid #e2e8f0' }}>
                                <h2 style={{ color: '#1e293b', margin: '0 0 20px', display: 'flex', alignItems:  'center', gap: '10px', fontSize: '18px', fontWeight: 700 }}>
                                    <ScanLine size={22} color="#2563eb" /> Intelligence Scanner
                                </h2>
                                <input value={input} onChange={e => setInput(e.target.value)} placeholder="Enter username or email address..." style={{ width: '100%', padding: '14px 16px', background: '#f8fafc', border: '2px solid #e2e8f0', borderRadius: '10px', color: '#1e293b', fontSize: '15px', marginBottom: '15px', outline: 'none', boxSizing: 'border-box' }} onFocus={e => e.target.style.borderColor = '#2563eb'} onBlur={e => e. target.style.borderColor = '#e2e8f0'} onKeyPress={e => e.key === 'Enter' && startScan('SOCIAL')} />
                                <div style={{ display: 'flex', gap: '12px' }}>
                                    <button onClick={() => startScan('SOCIAL')} disabled={scanning} style={{ flex: 1, padding: '14px', background: 'linear-gradient(135deg, #2563eb 0%, #1d4ed8 100%)', color: 'white', border:  'none', borderRadius: '10px', cursor: 'pointer', fontWeight: 600, fontSize: '14px', display: 'flex', alignItems: 'center', justifyContent: 'center', gap: '8px', opacity: scanning ? 0.7 : 1 }}>
                                        <Globe size={18} /> Social Media Scan
                                    </button>
                                    <button onClick={() => startScan('EMAIL')} disabled={scanning} style={{ flex: 1, padding: '14px', background: 'linear-gradient(135deg, #7c3aed 0%, #6d28d9 100%)', color: 'white', border: 'none', borderRadius: '10px', cursor: 'pointer', fontWeight: 600, fontSize:  '14px', display: 'flex', alignItems: 'center', justifyContent: 'center', gap: '8px', opacity: scanning ? 0.7 : 1 }}>
                                        <Mail size={18} /> Email Forensics
                                    </button>
                                </div>
                            </div>

                            {/* Target Details */}
                            {selectedTarget ?  (
                                <div style={{ background: 'white', borderRadius: '16px', padding:  '25px', boxShadow: '0 1px 3px rgba(0,0,0,0.1)', border: '1px solid #e2e8f0' }}>
                                    {/* Header */}
                                    <div style={{ display: 'flex', justifyContent: 'space-between', alignItems: 'center', marginBottom: '20px', paddingBottom: '15px', borderBottom: '1px solid #e2e8f0' }}>
                                        <h3 style={{ color: '#1e293b', margin: 0, display: 'flex', alignItems:  'center', gap: '10px', fontSize: '18px', fontWeight: 700 }}>
                                            <Target size={20} color="#2563eb" /> {selectedTarget.name}
                                        </h3>
                                        <div style={{ display: 'flex', gap: '8px', alignItems: 'center' }}>
                                            {selectedTarget.breach_count > 0 && <span style={{ background: '#fef2f2', color: '#dc2626', padding:  '6px 12px', borderRadius:  '20px', fontSize: '11px', fontWeight: 600, border: '1px solid #fecaca' }}>⚠️ {selectedTarget. breach_count} BREACH{selectedTarget.breach_count > 1 ? 'ES' : ''}</span>}
                                            <span style={{ background: getStatusBg(selectedTarget.status), color: getStatusColor(selectedTarget.status), padding: '6px 14px', borderRadius: '20px', fontSize: '12px', fontWeight: 600 }}>{selectedTarget.status || 'Unknown'}</span>
                                        </div>
                                    </div>

                                    {/* Trap Link */}
                                    <div style={{ background: '#f8fafc', borderRadius: '12px', padding:  '16px', marginBottom: '20px', border: '1px solid #e2e8f0' }}>
                                        <div style={{ color: '#64748b', fontSize: '11px', fontWeight: 700, marginBottom: '10px', display: 'flex', alignItems: 'center', gap: '6px', letterSpacing: '0.5px' }}>
                                            <Shield size={14} color="#2563eb" /> TRAP LINK
                                        </div>
                                        <div style={{ display: 'flex', gap: '10px' }}>
                                            <code style={{ flex: 1, background: 'white', padding: '12px 14px', borderRadius: '8px', color: '#2563eb', fontSize: '13px', wordBreak: 'break-all', border: '1px solid #e2e8f0', fontFamily: 'Monaco, Consolas, monospace' }}>{API}/meet/secure/{selectedTarget.name}</code>
                                            <button onClick={() => copyLink(selectedTarget.name)} style={{ padding: '12px 18px', background: '#2563eb', color: 'white', border: 'none', borderRadius: '8px', cursor:  'pointer', display: 'flex', alignItems:  'center', gap: '6px', fontWeight: 600, fontSize: '13px' }}><Copy size={16} /> Copy</button>
                                        </div>
                                    </div>

                                    {/* Captured Email */}
                                    {selectedTarget.real_email && (
                                        <div style={{ background: '#f0fdf4', borderRadius: '12px', padding: '20px', marginBottom: '20px', border: '1px solid #bbf7d0' }}>
                                            <div style={{ display: 'flex', alignItems: 'center', justifyContent: 'space-between', marginBottom: '15px' }}>
                                                <div style={{ display: 'flex', alignItems:  'center', gap: '10px' }}>
                                                    <div style={{ width: '40px', height: '40px', background: '#16a34a', borderRadius: '50%', display: 'flex', alignItems: 'center', justifyContent: 'center' }}><Mail size={20} color="white" /></div>
                                                    <div>
                                                        <div style={{ fontSize: '11px', color: '#166534', fontWeight: 600 }}>CAPTURED EMAIL</div>
                                                        <div style={{ fontSize: '18px', fontWeight: 700, color: '#166534' }}>{selectedTarget.real_email}</div>
                                                    </div>
                                                </div>
                                                {selectedTarget.email_provider && <span style={{ background: '#dcfce7', color: '#166534', padding: '4px 12px', borderRadius: '20px', fontSize: '11px', fontWeight: 600 }}>{selectedTarget.email_provider}</span>}
                                            </div>
                                            {/* Gravatar */}
                                            {(selectedTarget.gravatar_url || gravatarProfile) && (
                                                <div style={{ background: 'white', borderRadius: '10px', padding: '15px', border: '1px solid #bbf7d0' }}>
                                                    <div style={{ display: 'flex', alignItems: 'center', gap: '15px' }}>
                                                        {selectedTarget.gravatar_url && <img src={selectedTarget.gravatar_url} alt="Gravatar" style={{ width: '60px', height: '60px', borderRadius: '50%', border: '3px solid #16a34a' }} />}
                                                        <div style={{ flex: 1 }}>
                                                            <div style={{ fontSize: '11px', color: '#64748b', fontWeight: 600, marginBottom: '4px' }}>GRAVATAR PROFILE</div>
                                                            {gravatarProfile?. display_name && <div style={{ fontSize: '16px', fontWeight: 600, color: '#1e293b' }}>{gravatarProfile. display_name}</div>}
                                                            {gravatarProfile?.location && <div style={{ fontSize: '12px', color: '#64748b', display: 'flex', alignItems:  'center', gap: '4px', marginTop: '4px' }}><MapPin size={12} /> {gravatarProfile.location}</div>}
                                                            {gravatarProfile?.about && <div style={{ fontSize: '12px', color: '#475569', marginTop: '6px', fontStyle: 'italic' }}>"{gravatarProfile.about. substring(0, 100)}{gravatarProfile.about.length > 100 ? '...' : ''}"</div>}
                                                        </div>
                                                    </div>
                                                    {gravatarProfile?.accounts && gravatarProfile.accounts.length > 0 && (
                                                        <div style={{ marginTop: '12px', paddingTop: '12px', borderTop: '1px solid #e2e8f0' }}>
                                                            <div style={{ fontSize: '10px', color: '#64748b', fontWeight: 600, marginBottom: '8px' }}>LINKED ACCOUNTS</div>
                                                            <div style={{ display: 'flex', flexWrap: 'wrap', gap: '6px' }}>
                                                                {gravatarProfile.accounts.map((acc, i) => (
                                                                    <a key={i} href={acc. url} target="_blank" rel="noopener noreferrer" style={{ background: '#dbeafe', color: '#1d4ed8', padding: '4px 10px', borderRadius: '12px', fontSize: '11px', fontWeight: 500, textDecoration: 'none', display: 'flex', alignItems: 'center', gap: '4px' }}>{acc.platform} {acc.verified && <CheckCircle size={10} />}</a>
                                                                ))}
                                                            </div>
                                                        </div>
                                                    )}
                                                </div>
                                            )}
                                        </div>
                                    )}

                                    {/* EMAIL SECURITY ANALYSIS - NEW */}
                                    {/* EMAIL SECURITY ANALYSIS - ENHANCED WITH DETAILS */}
{selectedTarget. real_email && (selectedTarget.spf_policy || selectedTarget.dmarc_policy) && (
    <div style={{ background: '#f8fafc', borderRadius: '12px', padding: '20px', marginBottom: '20px', border: '1px solid #e2e8f0' }}>
        <SectionHeader title="EMAIL SECURITY ANALYSIS" icon={Shield} section="security" color="#64748b" />
        {expandedSections.security && (
            <>
                {/* Security Score Card */}
                {selectedTarget.security_score !== undefined && (
                    <div style={{ background: 'white', padding: '16px', borderRadius: '10px', marginBottom: '16px', border: '2px solid ' + (selectedTarget.security_score >= 80 ? '#16a34a' : selectedTarget.security_score >= 60 ? '#d97706' : '#dc2626') }}>
                        <div style={{ display: 'flex', alignItems: 'center', justifyContent: 'space-between', marginBottom: '12px' }}>
                            <div>
                                <div style={{ fontSize: '11px', color: '#64748b', fontWeight: 600, marginBottom: '4px' }}>OVERALL SECURITY SCORE</div>
                                <div style={{ fontSize:  '36px', fontWeight: 700, color: selectedTarget.security_score >= 80 ? '#16a34a' : selectedTarget.security_score >= 60 ? '#d97706' : '#dc2626' }}>
                                    {selectedTarget.security_score}<span style={{ fontSize: '20px', color: '#94a3b8' }}>/100</span>
                                </div>
                            </div>
                            <div style={{ textAlign: 'right' }}>
                                <div style={{ fontSize: '48px', fontWeight: 700, color: selectedTarget.security_score >= 80 ? '#16a34a' : selectedTarget.security_score >= 60 ? '#d97706' : '#dc2626' }}>
                                    {selectedTarget.security_grade || 'N/A'}
                                </div>
                                <div style={{ fontSize: '10px', color: '#64748b', fontWeight: 600 }}>SECURITY GRADE</div>
                            </div>
                        </div>
                        <div style={{ width: '100%', height: '8px', background: '#e2e8f0', borderRadius: '4px', overflow: 'hidden' }}>
                            <div style={{ width: `${selectedTarget.security_score}%`, height: '100%', background: selectedTarget.security_score >= 80 ? '#16a34a' : selectedTarget.security_score >= 60 ? '#d97706' : '#dc2626', transition: 'width 0.3s' }}></div>
                        </div>
                    </div>
                )}

                {/* SPF/DMARC/DKIM Grid */}
                <div style={{ display: 'grid', gridTemplateColumns: 'repeat(3, 1fr)', gap: '12px', marginBottom: '16px' }}>
                    {/* SPF */}
                    <div style={{ background: 'white', padding: '12px', borderRadius: '8px', border:  '1px solid #e2e8f0' }}>
                        <div style={{ color: '#94a3b8', fontSize: '10px', fontWeight: 600, marginBottom: '6px', display: 'flex', alignItems: 'center', gap: '4px' }}>
                            <Shield size={10} /> SPF POLICY
                        </div>
                        <div style={{ color: '#1e293b', fontWeight: 700, fontSize: '14px', marginBottom: '4px' }}>{selectedTarget.spf_policy}</div>
                        {selectedTarget.spf_strength && (
                            <div style={{ fontSize: '10px', color: '#64748b' }}>{selectedTarget.spf_strength}</div>
                        )}
                    </div>

                    {/* DMARC */}
                    <div style={{ background: 'white', padding: '12px', borderRadius:  '8px', border: '1px solid #e2e8f0' }}>
                        <div style={{ color: '#94a3b8', fontSize: '10px', fontWeight: 600, marginBottom: '6px', display: 'flex', alignItems:  'center', gap: '4px' }}>
                            <Lock size={10} /> DMARC POLICY
                        </div>
                        <div style={{ color: '#1e293b', fontWeight: 700, fontSize:  '14px', marginBottom: '4px' }}>{selectedTarget. dmarc_policy}</div>
                        {selectedTarget. dmarc_strength && (
                            <div style={{ fontSize: '10px', color: '#64748b' }}>{selectedTarget. dmarc_strength}</div>
                        )}
                    </div>

                    {/* Spoofing Risk */}
                    <div style={{ background: 'white', padding: '12px', borderRadius: '8px', border: '1px solid #e2e8f0' }}>
                        <div style={{ color:  '#94a3b8', fontSize: '10px', fontWeight:  600, marginBottom: '6px', display: 'flex', alignItems: 'center', gap: '4px' }}>
                            <AlertTriangle size={10} /> SPOOFING RISK
                        </div>
                        <div style={{ 
                            color: selectedTarget.spoofing_risk === 'CRITICAL' || selectedTarget.spoofing_risk === 'HIGH' ? '#dc2626' :   
                                   selectedTarget.spoofing_risk === 'MEDIUM' ? '#d97706' : '#16a34a', 
                            fontWeight: 700, 
                            fontSize: '14px' 
                        }}>
                            {selectedTarget.spoofing_risk}
                        </div>
                    </div>
                </div>

                {/* Detailed Analysis Sections */}
                {selectedTarget.security_strengths && parseJSON(selectedTarget.security_strengths) && parseJSON(selectedTarget.security_strengths).length > 0 && (
                    <div style={{ background: '#f0fdf4', padding: '12px', borderRadius: '8px', marginBottom: '12px', border: '1px solid #bbf7d0' }}>
                        <div style={{ fontSize: '11px', fontWeight: 700, color: '#166534', marginBottom: '8px' }}>✓ SECURITY STRENGTHS</div>
                        <ul style={{ margin: 0, paddingLeft: '20px', color: '#16a34a', fontSize: '11px', lineHeight: '1.8' }}>
                            {parseJSON(selectedTarget.security_strengths).map((strength, i) => (
                                <li key={i}>{strength}</li>
                            ))}
                        </ul>
                    </div>
                )}

                {selectedTarget.security_vulnerabilities && parseJSON(selectedTarget.security_vulnerabilities) && parseJSON(selectedTarget.security_vulnerabilities).length > 0 && (
                    <div style={{ background: '#fffbeb', padding: '12px', borderRadius: '8px', marginBottom: '12px', border: '1px solid #fde68a' }}>
                        <div style={{ fontSize: '11px', fontWeight: 700, color: '#92400e', marginBottom: '8px' }}>⚠️ VULNERABILITIES FOUND</div>
                        <ul style={{ margin: 0, paddingLeft: '20px', color: '#d97706', fontSize: '11px', lineHeight: '1.8' }}>
                            {parseJSON(selectedTarget.security_vulnerabilities).map((vuln, i) => (
                                <li key={i}>{vuln}</li>
                            ))}
                        </ul>
                    </div>
                )}

                {selectedTarget.security_critical && parseJSON(selectedTarget.security_critical) && parseJSON(selectedTarget.security_critical).length > 0 && (
                    <div style={{ background: '#fef2f2', padding: '12px', borderRadius: '8px', marginBottom: '12px', border: '1px solid #fecaca' }}>
                        <div style={{ fontSize: '11px', fontWeight: 700, color: '#dc2626', marginBottom: '8px' }}>🚨 CRITICAL ISSUES</div>
                        <ul style={{ margin: 0, paddingLeft: '20px', color: '#dc2626', fontSize:  '11px', lineHeight: '1.8' }}>
                            {parseJSON(selectedTarget. security_critical).map((issue, i) => (
                                <li key={i}>{issue}</li>
                            ))}
                        </ul>
                    </div>
                )}

                {/* Technical Details (Collapsible) */}
                {selectedTarget.spf_record && (
                    <details style={{ marginBottom: '12px' }}>
                        <summary style={{ cursor: 'pointer', padding: '10px', background: 'white', borderRadius: '6px', border: '1px solid #e2e8f0', fontSize: '12px', fontWeight:  600, color: '#475569' }}>
                            📋 View SPF Record
                        </summary>
                        <div style={{ marginTop: '8px', padding: '10px', background: '#f8fafc', borderRadius:  '6px', fontSize: '11px', fontFamily: 'Monaco, Consolas, monospace', wordBreak: 'break-all', color: '#1e293b' }}>
                            {selectedTarget.spf_record}
                        </div>
                    </details>
                )}

                {selectedTarget.dmarc_record && (
                    <details style={{ marginBottom: '12px' }}>
                        <summary style={{ cursor: 'pointer', padding: '10px', background: 'white', borderRadius: '6px', border: '1px solid #e2e8f0', fontSize: '12px', fontWeight: 600, color: '#475569' }}>
                            📋 View DMARC Record
                        </summary>
                        <div style={{ marginTop:  '8px', padding: '10px', background: '#f8fafc', borderRadius: '6px', fontSize: '11px', fontFamily: 'Monaco, Consolas, monospace', wordBreak: 'break-all', color: '#1e293b' }}>
                            {selectedTarget. dmarc_record}
                        </div>
                    </details>
                )}

                {/* Warnings */}
                {selectedTarget. spoofing_risk && ['CRITICAL', 'HIGH'].  includes(selectedTarget.spoofing_risk) && (
                    <div style={{ background: '#fef2f2', padding: '12px', borderRadius: '6px', border: '1px solid #fecaca' }}>
                        <div style={{ color: '#dc2626', fontSize: '12px', fontWeight:   600, marginBottom: '8px' }}>
                            ⚠️ WARNING:  This email domain has weak sender authentication! 
                        </div>
                        <div style={{ color: '#ef4444', fontSize: '11px' }}>
                            Attackers can easily impersonate emails from this domain.  Recipients may not be able to verify authenticity.
                        </div>
                    </div>
                )}
                
                {selectedTarget.disposable_email === 1 && (
                    <div style={{ background: '#fffbeb', padding: '10px 12px', borderRadius:   '6px', border: '1px solid #fde68a', marginTop: '8px' }}>
                        <div style={{ color: '#d97706', fontSize: '12px', fontWeight: 600 }}>
                            📧 Disposable/Temporary Email Detected
                        </div>
                    </div>
                )}
            </>
        )}
    </div>
)}

                                    {/* BREACH DETAILS - UPDATED */}
                                    {selectedTarget.breach_count > 0 && (
                                        <div style={{ background:  '#fef2f2', borderRadius: '12px', padding:  '20px', marginBottom: '20px', border: '1px solid #fecaca' }}>
                                            <SectionHeader title="DATA BREACH ANALYSIS" icon={AlertTriangle} section="breaches" count={selectedTarget.breach_count} color="#dc2626" />
                                            {expandedSections.breaches && (
                                                <>
                                                    {/* Show data source */}
                                                    {breachDetails && breachDetails.length > 0 && breachDetails[0].source && (
                                                        <div style={{ background: '#eff6ff', padding: '8px 12px', borderRadius:  '6px', marginBottom: '12px', fontSize: '11px', color: '#1e40af', fontWeight: 600 }}>
                                                            📡 Data Source: {breachDetails[0].source === 'HIBP_API' ? 'Have I Been Pwned API (Real-time)' : breachDetails[0].source === 'LOCAL_DB' ? 'Local Database (Fallback)' : 'Hybrid'}
                                                        </div>
                                                    )}
                                                    
                                                    <div style={{ background: '#fee2e2', padding: '12px', borderRadius: '8px', marginBottom: '15px', display: 'flex', alignItems:  'center', gap: '10px' }}>
                                                        <AlertTriangle size={20} color="#dc2626" />
                                                        <div>
                                                            <div style={{ color: '#dc2626', fontWeight: 600, fontSize: '14px' }}>⚠️ HIGH RISK:  Email found in {selectedTarget.breach_count} data breach(es)</div>
                                                            <div style={{ color:  '#b91c1c', fontSize: '12px', marginTop: '2px' }}>Password may be compromised.  Immediate action recommended.</div>
                                                        </div>
                                                    </div>
                                                    {breachDetails && breachDetails. length > 0 ?  (
                                                        <div style={{ display: 'flex', flexDirection: 'column', gap: '12px' }}>
                                                            {breachDetails.filter(b => ! b.is_spam_list && ! b.is_fabricated).map((breach, i) => (
                                                                <div key={i} style={{ background: 'white', borderRadius: '10px', padding: '15px', border: '1px solid #fecaca' }}>
                                                                    <div style={{ display: 'flex', justifyContent: 'space-between', alignItems: 'flex-start', marginBottom: '10px' }}>
                                                                        <div>
                                                                            <div style={{ fontSize: '15px', fontWeight: 700, color: '#1e293b', display: 'flex', alignItems:  'center', gap: '8px' }}>
                                                                                <Database size={16} color="#dc2626" />
                                                                                {breach.title || breach.name}
                                                                            </div>
                                                                            {breach.domain && <div style={{ fontSize: '11px', color: '#64748b', marginTop: '2px' }}>Domain: {breach.domain}</div>}
                                                                            {breach.date && breach.date !== 'N/A' && (
                                                                                <div style={{ fontSize: '12px', color: '#64748b', marginTop: '4px', display: 'flex', alignItems: 'center', gap: '4px' }}>
                                                                                    <Calendar size={12} /> Breach Date: {breach.date}
                                                                                </div>
                                                                            )}
                                                                        </div>
                                                                        <div style={{ display: 'flex', gap: '6px', alignItems: 'center', flexWrap: 'wrap', justifyContent: 'flex-end' }}>
                                                                            <SeverityBadge severity={breach.severity} />
                                                                            {breach.is_verified && <span style={{ background: '#dcfce7', color: '#166534', padding: '2px 6px', borderRadius: '4px', fontSize: '9px', fontWeight: 600 }}>VERIFIED</span>}
                                                                            {breach.is_sensitive && <span style={{ background: '#fef2f2', color:  '#dc2626', padding: '2px 6px', borderRadius: '4px', fontSize: '9px', fontWeight: 600 }}>SENSITIVE</span>}
                                                                        </div>
                                                                    </div>
                                                                    {breach.records > 0 && (
                                                                        <div style={{ fontSize: '13px', color: '#475569', marginBottom: '8px' }}>
                                                                            <strong>{formatNumber(breach.records)}</strong> records exposed
                                                                        </div>
                                                                    )}
                                                                    {breach.description && (
                                                                        <div style={{ fontSize: '12px', color: '#64748b', marginBottom: '10px', lineHeight: '1.5' }}>
                                                                            {breach.description}
                                                                        </div>
                                                                    )}
                                                                    {breach.data_types && breach.data_types.length > 0 && (
                                                                        <div>
                                                                            <div style={{ fontSize: '10px', color: '#64748b', fontWeight: 600, marginBottom:  '6px' }}>EXPOSED DATA TYPES: </div>
                                                                            <div style={{ display: 'flex', flexWrap: 'wrap', gap: '4px' }}>
                                                                                {breach.data_types.map((type, j) => (
                                                                                    <span key={j} style={{ 
                                                                                        background: type. toLowerCase().includes('password') ? '#fee2e2' : '#f1f5f9', 
                                                                                        color: type.toLowerCase().includes('password') ? '#dc2626' : '#475569', 
                                                                                        padding: '3px 8px', 
                                                                                        borderRadius: '4px', 
                                                                                        fontSize: '10px', 
                                                                                        fontWeight: 500, 
                                                                                        display: 'flex', 
                                                                                        alignItems:  'center', 
                                                                                        gap: '3px' 
                                                                                    }}>
                                                                                        {type. toLowerCase().includes('password') && <Lock size={10} />}
                                                                                        {type}
                                                                                    </span>
                                                                                ))}
                                                                            </div>
                                                                        </div>
                                                                    )}
                                                                </div>
                                                            ))}
                                                        </div>
                                                    ) : selectedTarget.breaches ?  (
                                                        <div style={{ background: 'white', padding: '12px', borderRadius: '8px', border: '1px solid #fecaca' }}>
                                                            <div style={{ fontSize: '12px', color: '#dc2626', fontWeight: 500 }}>Breaches:  {selectedTarget.breaches}</div>
                                                        </div>
                                                    ) : null}
                                                    <div style={{ background: '#fffbeb', padding: '12px', borderRadius: '8px', marginTop: '15px', border: '1px solid #fde68a' }}>
                                                        <div style={{ fontSize: '11px', fontWeight: 700, color: '#92400e', marginBottom: '8px' }}>⚡ SECURITY RECOMMENDATIONS</div>
                                                        <ul style={{ margin: 0, paddingLeft: '20px', color: '#a16207', fontSize: '12px', lineHeight: '1.8' }}>
                                                            <li>Change password immediately on all accounts</li>
                                                            <li>Enable Two-Factor Authentication (2FA)</li>
                                                            <li>Use a password manager with unique passwords</li>
                                                            <li>Monitor bank statements for unauthorized transactions</li>
                                                        </ul>
                                                    </div>
                                                </>
                                            )}
                                        </div>
                                    )}

                                    {/* LINKED ACCOUNTS - UPDATED */}
                                    {linkedAccountsDetails && linkedAccountsDetails. length > 0 && (
                                        <div style={{ background: '#eff6ff', borderRadius: '12px', padding:  '20px', marginBottom: '20px', border: '1px solid #bfdbfe' }}>
                                            <SectionHeader title="LINKED SOCIAL ACCOUNTS" icon={Globe} section="accounts" count={linkedAccountsDetails.filter(a => a.exists === true).length} color="#2563eb" />
                                            {expandedSections.accounts && (
                                                <div style={{ display: 'grid', gridTemplateColumns: 'repeat(auto-fill, minmax(280px, 1fr))', gap: '12px' }}>
                                                    {linkedAccountsDetails.map((account, i) => (
                                                        <div key={i} style={{
                                                            background: 'white',
                                                            borderRadius:  '10px',
                                                            padding: '15px',
                                                            border: `1px solid ${account.exists === true ? '#bbf7d0' : account.status === 'MANUAL' ? '#fde68a' : account.exists === false ? '#f1f5f9' : '#fecaca'}`
                                                        }}>
                                                            <div style={{ display: 'flex', justifyContent: 'space-between', alignItems: 'flex-start', marginBottom: '10px' }}>
                                                                <div style={{ display: 'flex', alignItems: 'center', gap:  '10px', flex: 1 }}>
                                                                    {account.details?. avatar && (
                                                                        <img src={account.details.avatar} alt="" style={{ width: '36px', height: '36px', borderRadius: '50%', border: '2px solid #e2e8f0' }} />
                                                                    )}
                                                                    <div style={{ flex: 1, minWidth: 0 }}>
                                                                        <div style={{ fontSize: '14px', fontWeight: 700, color: '#1e293b' }}>{account.platform}</div>
                                                                        {account.details?.username && (
                                                                            <div style={{ fontSize: '12px', color: '#64748b', overflow: 'hidden', textOverflow: 'ellipsis', whiteSpace: 'nowrap' }}>@{account.details.username}</div>
                                                                        )}
                                                                    </div>
                                                                </div>
                                                                {/* Status Badge */}
                                                                {account.exists === true ?  (
                                                                    <span style={{ background: '#dcfce7', color: '#166534', padding: '3px 8px', borderRadius:  '4px', fontSize: '10px', fontWeight: 600, whiteSpace: 'nowrap' }}>
                                                                        ✓ FOUND
                                                                    </span>
                                                                ) : account.status === 'MANUAL' ? (
                                                                    <span style={{ background: '#fef3c7', color: '#92400e', padding: '3px 8px', borderRadius: '4px', fontSize: '10px', fontWeight: 600, whiteSpace: 'nowrap' }}>
                                                                        🔗 MANUAL
                                                                    </span>
                                                                ) : account.exists === false ? (
                                                                    <span style={{ background: '#f1f5f9', color: '#64748b', padding: '3px 8px', borderRadius: '4px', fontSize: '10px', fontWeight: 600, whiteSpace: 'nowrap' }}>
                                                                        ✗ NOT FOUND
                                                                    </span>
                                                                ) : (
                                                                    <span style={{ background: '#fef2f2', color: '#dc2626', padding: '3px 8px', borderRadius: '4px', fontSize: '10px', fontWeight: 600, whiteSpace: 'nowrap' }}>
                                                                        {account.status}
                                                                    </span>
                                                                )}
                                                            </div>

                                                            {/* Show details only for FOUND accounts */}
                                                            {account.exists === true && account.details && Object.keys(account.details).length > 0 && (
                                                                <div style={{ fontSize: '11px', color: '#475569', display: 'flex', flexDirection: 'column', gap: '4px', marginBottom: '10px' }}>
                                                                    {account.details.name && <div><strong>Name:</strong> {account.details.name}</div>}
                                                                    {account.details.bio && <div style={{ fontStyle: 'italic', color:  '#64748b' }}>"{account.details.bio. substring(0, 60)}{account.details.bio.length > 60 ? '...' :  ''}"</div>}
                                                                    {account.details.location && <div><strong>Location: </strong> {account.details.location}</div>}
                                                                    {account.details.followers !== undefined && <div><strong>Followers:</strong> {formatNumber(account.details.followers)}</div>}
                                                                    {account.details.karma !== undefined && <div><strong>Karma:</strong> {formatNumber(account.details.karma)}</div>}
                                                                    {account.details.public_repos !== undefined && <div><strong>Repos:</strong> {account.details.public_repos}</div>}
                                                                </div>
                                                            )}

                                                            {/* Note for manual check */}
                                                            {account.status === 'MANUAL' && account.note && (
                                                                <div style={{ fontSize: '10px', color: '#92400e', marginBottom: '8px', fontStyle: 'italic' }}>
                                                                    ⚠️ {account.note}
                                                                </div>
                                                            )}

                                                            {/* Profile Link Button */}
                                                            <a
                                                                href={account. url}
                                                                target="_blank"
                                                                rel="noopener noreferrer"
                                                                style={{
                                                                    display: 'flex',
                                                                    alignItems: 'center',
                                                                    justifyContent: 'center',
                                                                    gap: '6px',
                                                                    padding: '8px',
                                                                    background: account.exists === true ? '#eff6ff' : account.status === 'MANUAL' ? '#fffbeb' : '#f8fafc',
                                                                    color: account.exists === true ? '#2563eb' : account.status === 'MANUAL' ? '#92400e' : '#64748b',
                                                                    borderRadius: '6px',
                                                                    fontSize: '11px',
                                                                    fontWeight: 600,
                                                                    textDecoration: 'none',
                                                                    border: `1px solid ${account.exists === true ? '#bfdbfe' : account.status === 'MANUAL' ? '#fde68a' : '#e2e8f0'}`
                                                                }}
                                                            >
                                                                <ExternalLink size={12} />
                                                                {account.status === 'MANUAL' ? 'Open & Verify' : account.exists === true ? 'View Profile' : 'Check Link'}
                                                            </a>
                                                        </div>
                                                    ))}
                                                </div>
                                            )}
                                        </div>
                                    )}

                                    {/* Simple Linked Accounts fallback */}
                                    {!linkedAccountsDetails && selectedTarget.linked_accounts && (
                                        <div style={{ background: '#eff6ff', borderRadius: '12px', padding: '16px', marginBottom: '20px', border: '1px solid #bfdbfe' }}>
                                            <div style={{ color: '#1d4ed8', fontSize: '11px', fontWeight: 700, marginBottom: '10px', display: 'flex', alignItems: 'center', gap: '6px' }}><Globe size={14} /> LINKED ACCOUNTS</div>
                                            <div style={{ display:  'flex', flexWrap: 'wrap', gap:  '6px' }}>
                                                {selectedTarget.linked_accounts.split(',').map((acc, i) => (
                                                    <span key={i} style={{ background: '#dbeafe', color: '#1d4ed8', padding: '6px 12px', borderRadius:  '12px', fontSize: '12px', fontWeight: 500 }}>{acc. trim()}</span>
                                                ))}
                                            </div>
                                        </div>
                                    )}

                                    {/* Info Grid */}
                                    <div style={{ display: 'grid', gridTemplateColumns: 'repeat(2, 1fr)', gap: '12px', marginBottom: '20px' }}>
                                        <div style={{ background: '#f8fafc', padding: '16px', borderRadius: '10px', border: '1px solid #e2e8f0' }}>
                                            <div style={{ color: '#64748b', fontSize: '10px', fontWeight: 700, marginBottom: '6px', letterSpacing: '0.5px' }}>IP ADDRESS</div>
                                            <div style={{ color: '#1e293b', fontSize: '15px', fontWeight: 600 }}>{selectedTarget.ip || 'Not captured'}</div>
                                            {selectedTarget.isp && <div style={{ color:  '#64748b', fontSize: '11px', marginTop: '4px' }}>{selectedTarget.isp}</div>}
                                        </div>
                                        <div style={{ background: '#f8fafc', padding: '16px', borderRadius: '10px', border:  '1px solid #e2e8f0' }}>
                                            <div style={{ color:  '#64748b', fontSize: '10px', fontWeight: 700, marginBottom: '6px', letterSpacing: '0.5px' }}>GPS COORDINATES</div>
                                            <div style={{ color: '#1e293b', fontSize: '15px', fontWeight: 600 }}>{selectedTarget.lat && selectedTarget.lon ? `${selectedTarget.lat.toFixed(5)}, ${selectedTarget.lon. toFixed(5)}` : 'Not captured'}</div>
                                            {selectedTarget.accuracy > 0 && <div style={{ color: '#16a34a', fontSize: '11px', marginTop: '4px' }}>Accuracy: ±{Math.round(selectedTarget.accuracy)}m</div>}
                                        </div>
                                        <div style={{ background: '#f8fafc', padding: '16px', borderRadius: '10px', border: '1px solid #e2e8f0' }}>
                                            <div style={{ color: '#64748b', fontSize: '10px', fontWeight: 700, marginBottom: '6px', letterSpacing: '0.5px' }}>IP LOCATION</div>
                                            <div style={{ color: '#1e293b', fontSize: '15px', fontWeight: 600 }}>{selectedTarget.city && selectedTarget.country ? `${selectedTarget.city}, ${selectedTarget.country}` : 'Unknown'}</div>
                                            {selectedTarget.region && <div style={{ color: '#64748b', fontSize: '11px', marginTop: '4px' }}>{selectedTarget.region}</div>}
                                        </div>
                                        <div style={{ background: '#f8fafc', padding: '16px', borderRadius: '10px', border: '1px solid #e2e8f0' }}>
                                            <div style={{ color: '#64748b', fontSize: '10px', fontWeight: 700, marginBottom: '6px', letterSpacing: '0.5px' }}>LAST SEEN</div>
                                            <div style={{ color: '#1e293b', fontSize: '13px', fontWeight: 600 }}>{selectedTarget.last_seen || 'N/A'}</div>
                                        </div>
                                    </div>

                                    {/* Device Fingerprint */}
                                    {(selectedTarget.browser || selectedTarget.os || selectedTarget.screen_resolution) && (
                                        <div style={{ background: '#f8fafc', borderRadius: '12px', padding: '20px', marginBottom: '20px', border:  '1px solid #e2e8f0' }}>
                                            <SectionHeader title="DEVICE FINGERPRINT" icon={Fingerprint} section="device" color="#64748b" />
                                            {expandedSections.device && (
                                                <div style={{ display: 'grid', gridTemplateColumns: 'repeat(3, 1fr)', gap: '12px', fontSize: '12px' }}>
                                                    {selectedTarget.browser && <div style={{ background: 'white', padding: '12px', borderRadius: '8px', border: '1px solid #e2e8f0' }}><div style={{ color: '#94a3b8', fontSize: '10px', fontWeight:  600, marginBottom: '4px' }}>BROWSER</div><div style={{ color: '#1e293b', fontWeight: 500 }}>{selectedTarget.browser}</div></div>}
                                                    {selectedTarget.os && <div style={{ background: 'white', padding:  '12px', borderRadius: '8px', border: '1px solid #e2e8f0' }}><div style={{ color:  '#94a3b8', fontSize: '10px', fontWeight:  600, marginBottom: '4px' }}>OS</div><div style={{ color: '#1e293b', fontWeight: 500 }}>{selectedTarget.os}</div></div>}
                                                    {selectedTarget.screen_resolution && <div style={{ background:  'white', padding: '12px', borderRadius: '8px', border: '1px solid #e2e8f0' }}><div style={{ color: '#94a3b8', fontSize: '10px', fontWeight: 600, marginBottom: '4px' }}>SCREEN</div><div style={{ color: '#1e293b', fontWeight:  500 }}>{selectedTarget. screen_resolution}</div></div>}
                                                    {selectedTarget.timezone && <div style={{ background: 'white', padding: '12px', borderRadius: '8px', border: '1px solid #e2e8f0' }}><div style={{ color: '#94a3b8', fontSize: '10px', fontWeight: 600, marginBottom: '4px' }}>TIMEZONE</div><div style={{ color: '#1e293b', fontWeight: 500 }}>{selectedTarget.timezone}</div></div>}
                                                    {selectedTarget.language && <div style={{ background: 'white', padding: '12px', borderRadius: '8px', border: '1px solid #e2e8f0' }}><div style={{ color: '#94a3b8', fontSize: '10px', fontWeight: 600, marginBottom: '4px' }}>LANGUAGE</div><div style={{ color: '#1e293b', fontWeight: 500 }}>{selectedTarget.language}</div></div>}
                                                    {selectedTarget.cpu_cores && <div style={{ background: 'white', padding: '12px', borderRadius: '8px', border: '1px solid #e2e8f0' }}><div style={{ color: '#94a3b8', fontSize: '10px', fontWeight: 600, marginBottom: '4px' }}>CPU CORES</div><div style={{ color: '#1e293b', fontWeight: 500 }}>{selectedTarget.cpu_cores}</div></div>}
                                                </div>
                                            )}
                                        </div>
                                    )}

                                    {/* Status Alerts */}
                                    {selectedTarget.is_vpn && (
                                        <div style={{ background: '#fef2f2', border: '1px solid #fecaca', padding: '14px', borderRadius: '10px', marginBottom: '15px', display: 'flex', alignItems: 'center', gap: '12px' }}>
                                            <WifiOff size={20} color="#dc2626" />
                                            <div>
                                                <div style={{ color: '#dc2626', fontWeight: 600, fontSize: '13px' }}>VPN/Proxy Detected</div>
                                                <div style={{ color: '#ef4444', fontSize: '12px' }}>Target may be using anonymization.  Confidence: {selectedTarget.vpn_confidence || 0}%{selectedTarget.vpn_reasons && ` (${selectedTarget.vpn_reasons})`}</div>
                                            </div>
                                        </div>
                                    )}

                                    {selectedTarget.is_localhost && ! selectedTarget.is_vpn && (
                                        <div style={{ background: '#fffbeb', border: '1px solid #fde68a', padding: '14px', borderRadius: '10px', marginBottom: '15px', display: 'flex', alignItems:  'center', gap: '12px' }}>
                                            <AlertCircle size={20} color="#d97706" />
                                            <div>
                                                <div style={{ color: '#d97706', fontWeight: 600, fontSize: '13px' }}>Local Network Detected</div>
                                                <div style={{ color: '#f59e0b', fontSize: '12px' }}>GPS coordinates may be IP-based approximation. </div>
                                            </div>
                                        </div>
                                    )}

                                    {selectedTarget.status?. includes('DENIED') && (
                                        <div style={{ background: '#fef2f2', border: '1px solid #fecaca', padding: '14px', borderRadius:  '10px', marginBottom: '15px', display: 'flex', alignItems: 'center', gap: '12px' }}>
                                            <AlertCircle size={20} color="#dc2626" />
                                            <div>
                                                <div style={{ color: '#dc2626', fontWeight: 600, fontSize: '13px' }}>Location Permission Denied</div>
                                                <div style={{ color: '#ef4444', fontSize: '12px' }}>Target denied GPS access. Only IP-based data was captured.</div>
                                            </div>
                                        </div>
                                    )}

                                    {! selectedTarget.is_vpn && ! selectedTarget.is_localhost && selectedTarget.ip && ! selectedTarget.status?.includes('DENIED') && selectedTarget.lat && (
                                        <div style={{ background: '#f0fdf4', border: '1px solid #bbf7d0', padding: '14px', borderRadius: '10px', marginBottom: '15px', display: 'flex', alignItems: 'center', gap:  '12px' }}>
                                            <Wifi size={20} color="#16a34a" />
                                            <div>
                                                <div style={{ color: '#16a34a', fontWeight: 600, fontSize: '13px' }}>Clean Connection - High Accuracy</div>
                                                <div style={{ color: '#22c55e', fontSize: '12px' }}>Residential IP detected. GPS location data is accurate.</div>
                                            </div>
                                        </div>
                                    )}

                                    {/* OSINT Logs */}
                                    {selectedTarget.osint_log && (
                                        <div>
                                            <div style={{ color: '#64748b', fontSize:  '10px', fontWeight: 700, marginBottom: '10px', letterSpacing: '0.5px', display: 'flex', alignItems: 'center', gap: '6px' }}><Eye size={12} /> RAW INTELLIGENCE LOGS</div>
                                            <pre style={{ background: '#1e293b', color: '#4ade80', padding: '20px', borderRadius: '10px', fontSize: '11px', lineHeight: '1.7', maxHeight: '400px', overflow:  'auto', whiteSpace: 'pre-wrap', margin: 0, fontFamily: 'Monaco, Consolas, "Courier New", monospace' }}>{selectedTarget.osint_log}</pre>
                                        </div>
                                    )}

                                    {/* View on Map */}
                                    {selectedTarget.lat && selectedTarget. lon && (
                                        <button onClick={() => setView('MAP')} style={{ marginTop: '20px', width: '100%', padding: '14px', background: '#f1f5f9', color: '#475569', border: '1px solid #e2e8f0', borderRadius: '10px', cursor: 'pointer', fontWeight: 600, fontSize: '14px', display: 'flex', alignItems: 'center', justifyContent: 'center', gap: '8px' }}>
                                            <MapPin size={18} /> View Location on Map
                                        </button>
                                    )}
                                </div>
                            ) : (
                                <div style={{ background: 'white', borderRadius: '16px', padding: '60px 40px', textAlign: 'center', border:  '1px solid #e2e8f0' }}>
                                    <Target size={56} color="#cbd5e1" style={{ marginBottom: '20px' }} />
                                    <div style={{ color: '#475569', fontSize: '18px', fontWeight: 600, marginBottom: '8px' }}>Select a target from the sidebar</div>
                                    <div style={{ color: '#94a3b8', fontSize: '14px' }}>Or start a new scan above to add targets</div>
                                </div>
                            )}
                        </div>
                    </div>
                )}
            </div>
        </div>
    );
}