-- Add total_price column to events table
ALTER TABLE events
ADD COLUMN IF NOT EXISTS total_price DECIMAL(10, 2);
