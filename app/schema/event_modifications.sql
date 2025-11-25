-- Create table to track modifications to event services
CREATE TABLE IF NOT EXISTS modified_event_services (
    modification_id SERIAL PRIMARY KEY,
    event_id INTEGER REFERENCES events(events_id),
    package_service_id INTEGER REFERENCES package_service(package_service_id),
    modification_type VARCHAR(20) CHECK (modification_type IN ('added', 'removed', 'modified')),
    original_price DECIMAL(10, 2),
    modified_price DECIMAL(10, 2),
    remarks TEXT,
    created_at TIMESTAMP DEFAULT CURRENT_TIMESTAMP
);

-- Create table for event-specific service customizations
CREATE TABLE IF NOT EXISTS event_service_customizations (
    customization_id SERIAL PRIMARY KEY,
    event_id INTEGER REFERENCES events(events_id),
    package_service_id INTEGER REFERENCES package_service(package_service_id),
    custom_price DECIMAL(10, 2),
    custom_details JSONB,
    created_at TIMESTAMP DEFAULT CURRENT_TIMESTAMP
);

-- Add indexes for better query performance
CREATE INDEX idx_modified_event_services_event_id ON modified_event_services(event_id);
CREATE INDEX idx_event_service_customizations_event_id ON event_service_customizations(event_id);

-- Add columns to events table for storing modifications
ALTER TABLE events ADD COLUMN IF NOT EXISTS modified_suppliers JSONB;
ALTER TABLE events ADD COLUMN IF NOT EXISTS modified_venues JSONB;

-- Create table for event-specific suppliers
CREATE TABLE IF NOT EXISTS event_suppliers (
    event_supplier_id SERIAL PRIMARY KEY,
    events_id INTEGER REFERENCES events(events_id),
    supplier_id INTEGER REFERENCES suppliers(supplier_id),
    is_modified BOOLEAN DEFAULT FALSE,
    is_removed BOOLEAN DEFAULT FALSE,
    modified_price DECIMAL(10,2),
    external_supplier_name VARCHAR(255),
    external_supplier_contact VARCHAR(255),
    external_supplier_price DECIMAL(10,2),
    remarks TEXT,
    created_at TIMESTAMP DEFAULT CURRENT_TIMESTAMP
);

-- Create table for event-specific venues
CREATE TABLE IF NOT EXISTS event_venues (
    event_venue_id SERIAL PRIMARY KEY,
    events_id INTEGER REFERENCES events(events_id),
    venue_id INTEGER REFERENCES venues(venue_id),
    is_modified BOOLEAN DEFAULT FALSE,
    is_removed BOOLEAN DEFAULT FALSE,
    modified_price DECIMAL(10,2),
    remarks TEXT,
    created_at TIMESTAMP DEFAULT CURRENT_TIMESTAMP
);

-- Add indexes for better query performance
CREATE INDEX IF NOT EXISTS idx_event_suppliers_events_id ON event_suppliers(events_id);
CREATE INDEX IF NOT EXISTS idx_event_venues_events_id ON event_venues(events_id);
