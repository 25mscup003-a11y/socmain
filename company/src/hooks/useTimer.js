import { useState, useEffect, useCallback, useRef } from 'react';

/**
 * Custom Hook for Countdown Timer
 * Useful for OTP resend, button cooldowns, etc.
 * 
 * Usage:
 * const { timeLeft, isRunning, start, reset, stop } = useTimer(30);
 * 
 * <button disabled={isRunning}>
 *   Resend OTP {isRunning && `in ${timeLeft}s`}
 * </button>
 */
const useTimer = (initialSeconds = 60) => {
  const [timeLeft, setTimeLeft] = useState(initialSeconds);
  const [isRunning, setIsRunning] = useState(false);
  const intervalRef = useRef(null);

  /**
   * Start the timer countdown
   */
  const start = useCallback(() => {
    setIsRunning(true);
    setTimeLeft(initialSeconds);
  }, [initialSeconds]);

  /**
   * Stop the timer
   */
  const stop = useCallback(() => {
    setIsRunning(false);
    if (intervalRef.current) {
      clearInterval(intervalRef.current);
    }
  }, []);

  /**
   * Reset the timer
   */
  const reset = useCallback(() => {
    stop();
    setTimeLeft(initialSeconds);
  }, [initialSeconds, stop]);

  /**
   * Effect for countdown logic
   */
  useEffect(() => {
    if (!isRunning) {
      return;
    }

    intervalRef.current = setInterval(() => {
      setTimeLeft((prev) => {
        if (prev <= 1) {
          setIsRunning(false);
          if (intervalRef.current) {
            clearInterval(intervalRef.current);
          }
          return initialSeconds;
        }
        return prev - 1;
      });
    }, 1000);

    return () => {
      if (intervalRef.current) {
        clearInterval(intervalRef.current);
      }
    };
  }, [isRunning, initialSeconds]);

  /**
   * Get remaining time as formatted string
   * @returns {String} Formatted time (e.g., "00:30")
   */
  const getFormattedTime = useCallback(() => {
    const minutes = Math.floor(timeLeft / 60);
    const seconds = timeLeft % 60;
    return `${String(minutes).padStart(2, '0')}:${String(seconds).padStart(2, '0')}`;
  }, [timeLeft]);

  /**
   * Check if time has finished
   */
  const isFinished = timeLeft === initialSeconds && !isRunning;

  return {
    timeLeft,
    isRunning,
    isFinished,
    start,
    stop,
    reset,
    getFormattedTime,
    hasTimeLeft: timeLeft > 0,
  };
};

export default useTimer;
