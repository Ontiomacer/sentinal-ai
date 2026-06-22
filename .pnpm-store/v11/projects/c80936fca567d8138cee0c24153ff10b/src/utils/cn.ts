import { clsx, type ClassValue } from 'clsx';
import { twMerge } from 'tailwind-merge';

/**
 * Combine clsx and tailwind-merge for safe class name merging
 */
export function cn(...inputs: ClassValue[]) {
  return twMerge(clsx(inputs));
}
