/**
 * Centralized API Client for FastAPI Backend Communication
 */

const API_BASE_URL = import.meta.env.VITE_API_BASE_URL || '/api/v1';

async function request(endpoint, options = {}) {
  const url = `${API_BASE_URL}${endpoint}`;
  const token = localStorage.getItem('ecdat_token');

  const defaultHeaders = options.body instanceof FormData ? {} : { 'Content-Type': 'application/json' };
  if (token) {
    defaultHeaders['Authorization'] = `Bearer ${token}`;
  }
  
  const config = {
    ...options,
    headers: {
      ...defaultHeaders,
      ...options.headers,
    },
  };

  try {
    const response = await fetch(url, config);
    if (!response.ok) {
      const errorText = await response.text();
      let parsedMsg = errorText;
      try {
        const jsonErr = JSON.parse(errorText);
        parsedMsg = jsonErr.detail || jsonErr.message || errorText;
      } catch (e) {
        // use raw text
      }
      throw new Error(parsedMsg || `API Error ${response.status}`);
    }
    return await response.json();
  } catch (err) {
    console.error(`Fetch error on ${url}:`, err);
    throw err;
  }
}

// Authentication APIs
export async function loginApi(email, password) {
  return request('/auth/login', {
    method: 'POST',
    body: JSON.stringify({ email, password }),
  });
}

export async function registerApi(name, email, password) {
  return request('/auth/register', {
    method: 'POST',
    body: JSON.stringify({ name, email, password }),
  });
}

export async function getMeApi() {
  return request('/auth/me');
}

export async function forgotPasswordApi(email) {
  return request('/auth/forgot-password', {
    method: 'POST',
    body: JSON.stringify({ email }),
  });
}

export async function resetPasswordApi(email, otp, newPassword) {
  return request('/auth/reset-password', {
    method: 'POST',
    body: JSON.stringify({ email, otp, new_password: newPassword }),
  });
}


// Scan Management APIs
export async function uploadScanTarget(file, projectName = 'Default Project') {
  const formData = new FormData();
  formData.append('file', file);
  return request(`/scans/upload?project_name=${encodeURIComponent(projectName)}`, {
    method: 'POST',
    body: formData,
  });
}

export async function createScan(projectName = 'Default Project', targetName = 'Sample Scan') {
  return request('/scans', {
    method: 'POST',
    body: JSON.stringify({ project_name: projectName, target_name: targetName }),
  });
}

export async function listScans() {
  return request('/scans');
}

export async function getScanStatus(scanId) {
  return request(`/scans/${scanId}/status`);
}

export async function getScanFindings(scanId) {
  return request(`/scans/${scanId}/findings`);
}

export async function getScanCBOM(scanId) {
  return request(`/scans/${scanId}/cbom`);
}

export async function getScanCycloneDX(scanId) {
  return request(`/scans/${scanId}/cyclonedx`);
}

export async function getScanRisk(scanId) {
  return request(`/scans/${scanId}/risk`);
}

export async function getScanMosca(scanId) {
  return request(`/scans/${scanId}/mosca`);
}

export async function getScanMigration(scanId) {
  return request(`/scans/${scanId}/migration`);
}

export async function getScanRemediation(scanId) {
  return request(`/scans/${scanId}/remediation`);
}

export async function updateRemediationStatus(scanId, findingId, status, choice = 'bridge') {
  return request(`/scans/${scanId}/remediation/${findingId}/status`, {
    method: 'POST',
    body: JSON.stringify({ status, choice }),
  });
}

export async function getScanCompliance(scanId) {
  return request(`/scans/${scanId}/compliance`);
}

export async function runFindingPqcPrototype(scanId, findingId) {
  return request(`/scans/${scanId}/findings/${findingId}/prototype`, {
    method: 'POST',
  });
}

export async function getScanReminders(scanId) {
  return request(`/scans/${scanId}/reminders`);
}

export async function updateReminderAck(scanId, reminderId, acknowledged = true) {
  return request(`/scans/${scanId}/reminders/${reminderId}`, {
    method: 'POST',
    body: JSON.stringify({ acknowledged }),
  });
}

export async function deleteScan(scanId) {
  return request(`/scans/${scanId}`, {
    method: 'DELETE',
  });
}

export async function getSystemInfo() {
  return request('/system/info');
}
