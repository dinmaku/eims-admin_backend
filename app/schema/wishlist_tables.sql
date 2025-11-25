-- Create events table if not exists
CREATE TABLE IF NOT EXISTS events (
    events_id SERIAL PRIMARY KEY,
    event_name VARCHAR(255),
    event_type VARCHAR(255),
    event_theme VARCHAR(255),
    event_color VARCHAR(255),
    venue VARCHAR(255),
    created_at TIMESTAMP DEFAULT CURRENT_TIMESTAMP
);

-- Create venues table if not exists
CREATE TABLE IF NOT EXISTS venues (
    venue_id SERIAL PRIMARY KEY,
    venue_name VARCHAR(255),
    location TEXT,
    description TEXT,
    venue_price DECIMAL(10,2) DEFAULT 0,
    venue_capacity INTEGER,
    status VARCHAR(20) DEFAULT 'Active',
    created_at TIMESTAMP DEFAULT CURRENT_TIMESTAMP
);

-- Create gown_package table if not exists
CREATE TABLE IF NOT EXISTS gown_package (
    gown_package_id SERIAL PRIMARY KEY,
    gown_package_name VARCHAR(255),
    description TEXT,
    gown_package_price DECIMAL(10,2) DEFAULT 0,
    status VARCHAR(20) DEFAULT 'Active',
    created_at TIMESTAMP DEFAULT CURRENT_TIMESTAMP
);

-- Create event_types table if not exists
CREATE TABLE IF NOT EXISTS event_types (
    event_type_id SERIAL PRIMARY KEY,
    event_type_name VARCHAR(255),
    created_at TIMESTAMP DEFAULT CURRENT_TIMESTAMP
);

-- Create additional_services table if not exists
CREATE TABLE IF NOT EXISTS additional_services (
    add_service_id SERIAL PRIMARY KEY,
    add_service_name VARCHAR(255),
    add_service_description TEXT,
    add_service_price DECIMAL(10,2) DEFAULT 0,
    status VARCHAR(20) DEFAULT 'Active',
    created_at TIMESTAMP DEFAULT CURRENT_TIMESTAMP
);

-- Create outfits table if not exists
CREATE TABLE IF NOT EXISTS outfits (
    outfit_id SERIAL PRIMARY KEY,
    outfit_name VARCHAR(255),
    outfit_type VARCHAR(255),
    size VARCHAR(50),
    rent_price DECIMAL(10,2) DEFAULT 0,
    status VARCHAR(20) DEFAULT 'Active',
    created_at TIMESTAMP DEFAULT CURRENT_TIMESTAMP
);

-- Create suppliers table if not exists
CREATE TABLE IF NOT EXISTS suppliers (
    supplier_id SERIAL PRIMARY KEY,
    userid INTEGER,
    service VARCHAR(255),
    price DECIMAL(10,2) DEFAULT 0,
    status VARCHAR(20) DEFAULT 'Active',
    created_at TIMESTAMP DEFAULT CURRENT_TIMESTAMP
);

-- Create table for wishlist packages
CREATE TABLE IF NOT EXISTS wishlist_packages (
    wishlist_id SERIAL PRIMARY KEY,
    events_id INTEGER REFERENCES events(events_id),
    package_name VARCHAR(255),
    capacity INTEGER,
    description TEXT,
    venue_id INTEGER REFERENCES venues(venue_id),
    gown_package_id INTEGER REFERENCES gown_package(gown_package_id),
    additional_capacity_charges DECIMAL(10,2) DEFAULT 0,
    charge_unit INTEGER DEFAULT 1,
    total_price DECIMAL(10,2) DEFAULT 0,
    event_type_id INTEGER REFERENCES event_types(event_type_id),
    status VARCHAR(20) DEFAULT 'Active',
    created_at TIMESTAMP DEFAULT CURRENT_TIMESTAMP
);

-- Create table for wishlist package services
CREATE TABLE IF NOT EXISTS wishlist_package_services (
    wishlist_service_id SERIAL PRIMARY KEY,
    wishlist_id INTEGER REFERENCES wishlist_packages(wishlist_id),
    service_id INTEGER REFERENCES additional_services(add_service_id),
    price DECIMAL(10,2) DEFAULT 0,
    remarks TEXT,
    created_at TIMESTAMP DEFAULT CURRENT_TIMESTAMP
);

-- Create table for wishlist suppliers
CREATE TABLE IF NOT EXISTS wishlist_suppliers (
    wishlist_supplier_id SERIAL PRIMARY KEY,
    wishlist_id INTEGER REFERENCES wishlist_packages(wishlist_id),
    supplier_id INTEGER REFERENCES suppliers(supplier_id),
    price DECIMAL(10,2),
    remarks TEXT,
    created_at TIMESTAMP DEFAULT CURRENT_TIMESTAMP,
    status VARCHAR(20) DEFAULT 'Pending',
    has_been_updated BOOLEAN DEFAULT FALSE,
    external_supplier_name VARCHAR(255),
    external_supplier_contact VARCHAR(255)
);

-- Create table for wishlist outfits
CREATE TABLE IF NOT EXISTS wishlist_outfits (
    wishlist_outfit_id SERIAL PRIMARY KEY,
    wishlist_id INTEGER REFERENCES wishlist_packages(wishlist_id),
    outfit_id INTEGER REFERENCES outfits(outfit_id),
    gown_package_id INTEGER REFERENCES gown_package(gown_package_id),
    price DECIMAL(10,2),
    remarks TEXT,
    status VARCHAR(50) DEFAULT 'Pending',
    created_at TIMESTAMP DEFAULT CURRENT_TIMESTAMP
);

-- Add indexes for better query performance
CREATE INDEX IF NOT EXISTS idx_wishlist_packages_events_id ON wishlist_packages(events_id);
CREATE INDEX IF NOT EXISTS idx_wishlist_package_services_wishlist_id ON wishlist_package_services(wishlist_id);
CREATE INDEX IF NOT EXISTS idx_wishlist_suppliers_wishlist_id ON wishlist_suppliers(wishlist_id);
CREATE INDEX IF NOT EXISTS idx_wishlist_outfits_wishlist_id ON wishlist_outfits(wishlist_id);
