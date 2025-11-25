-- Add viewed column to events table if it doesn't exist
DO $$ 
BEGIN 
    IF NOT EXISTS (SELECT 1 FROM information_schema.columns 
                  WHERE table_name = 'events' AND column_name = 'viewed') THEN
        ALTER TABLE events ADD COLUMN viewed BOOLEAN DEFAULT FALSE;
    END IF;
END $$; 