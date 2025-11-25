-- Create event_specific_services table to store event-specific modifications
CREATE TABLE IF NOT EXISTS event_specific_services (
    event_service_id SERIAL PRIMARY KEY,
    events_id INTEGER NOT NULL,
    package_service_id INTEGER NOT NULL,
    is_modified BOOLEAN DEFAULT FALSE,
    created_at TIMESTAMP DEFAULT CURRENT_TIMESTAMP,
    FOREIGN KEY (events_id) REFERENCES events(events_id) ON DELETE CASCADE,
    FOREIGN KEY (package_service_id) REFERENCES package_service(package_service_id) ON DELETE CASCADE
);
