extern crate alloc;

use crate::error::SdkError;
use crate::prelude::*;
use alloc::collections::BTreeMap;

/// Simple in-memory database trait for no_std environments
pub trait Database {
    type Error;
    
    fn get(&self, key: &[u8]) -> Result<Option<Vec<u8>>, Self::Error>;
    fn set(&mut self, key: Vec<u8>, value: Vec<u8>) -> Result<(), Self::Error>;
    fn remove(&mut self, key: &[u8]) -> Result<Option<Vec<u8>>, Self::Error>;
}

/// Simple in-memory database implementation using BTreeMap
#[derive(Debug, Default)]
pub struct MemoryDB {
    data: BTreeMap<Vec<u8>, Vec<u8>>,
}

impl MemoryDB {
    pub fn new() -> Self {
        Self::default()
    }
}

impl Database for MemoryDB {
    type Error = SdkError;
    
    fn get(&self, key: &[u8]) -> Result<Option<Vec<u8>>, Self::Error> {
        Ok(self.data.get(key).cloned())
    }
    
    fn set(&mut self, key: Vec<u8>, value: Vec<u8>) -> Result<(), Self::Error> {
        self.data.insert(key, value);
        Ok(())
    }
    
    fn remove(&mut self, key: &[u8]) -> Result<Option<Vec<u8>>, Self::Error> {
        Ok(self.data.remove(key))
    }
}