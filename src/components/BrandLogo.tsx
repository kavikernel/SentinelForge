import React from 'react';

export const BrandLogo: React.FC<{ size?: number }> = ({ size = 28 }) => {
  return (
    <svg
      width={size}
      height={size}
      viewBox="0 0 36 36"
      fill="none"
      xmlns="http://www.w3.org/2000/svg"
      aria-hidden="true"
      className="shrink-0"
    >
      <path
        d="M18 3L5 8.2V16.8C5 24.7 10.55 31.85 18 33.8C25.45 31.85 31 24.7 31 16.8V8.2L18 3Z"
        fill="#0F172A"
        stroke="#3B82F6"
        strokeWidth="1.75"
      />
      <path
        d="M18 7.5L9.5 11V16.6C9.5 22.1 13.15 27.15 18 28.75C22.85 27.15 26.5 22.1 26.5 16.6V11L18 7.5Z"
        fill="#1E293B"
        stroke="#8B5CF6"
        strokeWidth="1.15"
        strokeOpacity="0.85"
      />
      <path
        d="M18 12V24M13 17.5H23M14.5 14L18 17.5L21.5 14"
        stroke="#60A5FA"
        strokeWidth="1.6"
        strokeLinecap="round"
        strokeLinejoin="round"
      />
      <circle cx="18" cy="12" r="1.6" fill="#A78BFA" />
      <circle cx="13" cy="17.5" r="1.4" fill="#3B82F6" />
      <circle cx="23" cy="17.5" r="1.4" fill="#3B82F6" />
      <circle cx="18" cy="24" r="1.6" fill="#60A5FA" />
    </svg>
  );
};
