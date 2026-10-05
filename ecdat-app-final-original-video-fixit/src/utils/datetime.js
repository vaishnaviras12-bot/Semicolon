/**
 * Shared Datetime Utilities for Local Timezone Display
 * Ensures ISO-8601 strings (with or without 'Z') are parsed as UTC
 * and rendered in the user's local browser timezone.
 */

export function parseISO(dateInput) {
  if (!dateInput) return null;
  if (dateInput instanceof Date) return dateInput;
  let str = String(dateInput).trim();
  if (!str) return null;
  
  // If naive ISO string (e.g. "2026-10-04T23:40:54" without timezone offset/Z), append 'Z' to treat as UTC
  if (/^\d{4}-\d{2}-\d{2}T\d{2}:\d{2}:\d{2}(\.\d+)?$/.test(str)) {
    str += 'Z';
  }
  const parsed = new Date(str);
  return isNaN(parsed.getTime()) ? null : parsed;
}

/**
 * Formats datetime as "04 Oct 2026, 3:45 PM" in local timezone
 */
export function formatDateTime(dateInput) {
  const dt = parseISO(dateInput);
  if (!dt) return 'N/A';
  
  return new Intl.DateTimeFormat('en-GB', {
    day: '2-digit',
    month: 'short',
    year: 'numeric',
    hour: 'numeric',
    minute: '2-digit',
    hour12: true,
  }).format(dt);
}

/**
 * Formats date as "04 Oct 2026" in local timezone
 */
export function formatDate(dateInput) {
  const dt = parseISO(dateInput);
  if (!dt) return 'N/A';

  return new Intl.DateTimeFormat('en-GB', {
    day: '2-digit',
    month: 'short',
    year: 'numeric',
  }).format(dt);
}

/**
 * Relative time string like "5 mins ago", "2 hours ago", "3 days ago", "Just now"
 */
export function timeAgo(dateInput) {
  const dt = parseISO(dateInput);
  if (!dt) return 'N/A';

  const diffMs = Date.now() - dt.getTime();
  const diffSecs = Math.floor(diffMs / 1000);
  if (diffSecs < 60) return 'Just now';
  
  const diffMins = Math.floor(diffSecs / 60);
  if (diffMins < 60) return `${diffMins} min${diffMins > 1 ? 's' : ''} ago`;

  const diffHours = Math.floor(diffMins / 60);
  if (diffHours < 24) return `${diffHours} hour${diffHours > 1 ? 's' : ''} ago`;

  const diffDays = Math.floor(diffHours / 24);
  if (diffDays < 30) return `${diffDays} day${diffDays > 1 ? 's' : ''} ago`;

  return formatDate(dt);
}

/**
 * Calculates integer days ago from current time
 */
export function daysAgo(dateInput) {
  const dt = parseISO(dateInput);
  if (!dt) return 0;
  const diffMs = Date.now() - dt.getTime();
  return Math.max(0, Math.floor(diffMs / (1000 * 60 * 60 * 24)));
}
