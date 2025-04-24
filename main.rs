// Blockchain Anomaly Detector
// A Rust application to analyze cryptocurrency transactions and detect potential
// wash trading or other illicit activities

use chrono::{DateTime, Utc};
use serde::{Deserialize, Serialize};
use std::collections::{HashMap, HashSet};
use std::error::Error;
use std::fs::File;
use std::io::BufReader;
use std::path::Path;
use std::time::{Duration, SystemTime};
use rand::Rng;

// Define core data structures
#[derive(Debug, Clone, Serialize, Deserialize)]
struct Transaction {
    tx_id: String,
    timestamp: DateTime<Utc>,
    from_address: String,
    to_address: String,
    amount: f64,
    fee: f64,
    currency: String,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
struct WalletProfile {
    address: String,
    transaction_count: usize,
    first_seen: DateTime<Utc>,
    last_seen: DateTime<Utc>,
    total_sent: f64,
    total_received: f64,
    connected_addresses: HashSet<String>,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
struct AnomalyReport {
    anomaly_type: AnomalyType,
    severity: u8, // 1-10 scale
    description: String,
    related_transactions: Vec<String>,
    related_addresses: Vec<String>,
    detection_time: DateTime<Utc>,
}

#[derive(Debug, Clone, PartialEq, Serialize, Deserialize)]
enum AnomalyType {
    WashTrading,
    CircularTransaction,
    StructuredTransactions,
    UnusualVolume,
    AddressClustering,
    SuspiciousNewWallet,
    TransactionSpike,
    PumpAndDump,
}

// Analyzer configuration
struct AnalyzerConfig {
    wash_trade_threshold: f64,
    circular_depth_search: usize,
    unusual_volume_factor: f64,
    structuring_threshold: f64,
    transaction_time_window: Duration,
    min_cluster_size: usize,
    volume_baseline_days: usize,
}

// Main data processor
struct BlockchainAnalyzer {
    transactions: Vec<Transaction>,
    wallet_profiles: HashMap<String, WalletProfile>,
    anomalies: Vec<AnomalyReport>,
    config: AnalyzerConfig,
}

impl BlockchainAnalyzer {
    fn new(config: AnalyzerConfig) -> Self {
        BlockchainAnalyzer {
            transactions: Vec::new(),
            wallet_profiles: HashMap::new(),
            anomalies: Vec::new(),
            config,
        }
    }

    fn load_transactions_from_file<P: AsRef<Path>>(&mut self, path: P) -> Result<(), Box<dyn Error>> {
        let file = File::open(path)?;
        let reader = BufReader::new(file);
        self.transactions = serde_json::from_reader(reader)?;
        Ok(())
    }

    fn build_wallet_profiles(&mut self) {
        let mut profiles: HashMap<String, WalletProfile> = HashMap::new();
        
        for tx in &self.transactions {
            // Sender profile
            let sender_profile = profiles.entry(tx.from_address.clone()).or_insert_with(|| WalletProfile {
                address: tx.from_address.clone(),
                transaction_count: 0,
                first_seen: tx.timestamp,
                last_seen: tx.timestamp,
                total_sent: 0.0,
                total_received: 0.0,
                connected_addresses: HashSet::new(),
            });
            sender_profile.transaction_count += 1;
            sender_profile.total_sent += tx.amount;
            sender_profile.first_seen = sender_profile.first_seen.min(tx.timestamp);
            sender_profile.last_seen = sender_profile.last_seen.max(tx.timestamp);
            sender_profile.connected_addresses.insert(tx.to_address.clone());
            
            // Recipient profile
            let recipient_profile = profiles.entry(tx.to_address.clone()).or_insert_with(|| WalletProfile {
                address: tx.to_address.clone(),
                transaction_count: 0,
                first_seen: tx.timestamp,
                last_seen: tx.timestamp,
                total_sent: 0.0,
                total_received: 0.0,
                connected_addresses: HashSet::new(),
            });
            recipient_profile.transaction_count += 1;
            recipient_profile.total_received += tx.amount;
            recipient_profile.first_seen = recipient_profile.first_seen.min(tx.timestamp);
            recipient_profile.last_seen = recipient_profile.last_seen.max(tx.timestamp);
            recipient_profile.connected_addresses.insert(tx.from_address.clone());
        }
        
        self.wallet_profiles = profiles;
    }

    fn detect_anomalies(&mut self) {
        self.detect_wash_trading();
        self.detect_circular_transactions();
        self.detect_structured_transactions();
        self.detect_unusual_volume();
        self.detect_address_clustering();
        self.detect_suspicious_new_wallets();
        self.detect_transaction_spikes();
        // Note: PumpAndDump detection is not implemented here but can be added later
    }

    fn detect_wash_trading(&mut self) {
        let mut bidirectional_txs: HashMap<(String, String), Vec<Transaction>> = HashMap::new();
        
        for tx in &self.transactions {
            let pair = if tx.from_address < tx.to_address {
                (tx.from_address.clone(), tx.to_address.clone())
            } else {
                (tx.to_address.clone(), tx.from_address.clone())
            };
            bidirectional_txs.entry(pair).or_default().push(tx.clone());
        }
        
        for ((addr1, addr2), transactions) in bidirectional_txs {
            if transactions.len() < 3 { continue; }
            
            let mut a_to_b_amount = 0.0;
            let mut b_to_a_amount = 0.0;
            let mut a_to_b_txs = Vec::new();
            let mut b_to_a_txs = Vec::new();
            
            for tx in &transactions {
                if tx.from_address == addr1 && tx.to_address == addr2 {
                    a_to_b_amount += tx.amount;
                    a_to_b_txs.push(tx.tx_id.clone());
                } else {
                    b_to_a_amount += tx.amount;
                    b_to_a_txs.push(tx.tx_id.clone());
                }
            }
            
            if !a_to_b_txs.is_empty() && !b_to_a_txs.is_empty() {
                let ratio = if a_to_b_amount > b_to_a_amount {
                    b_to_a_amount / a_to_b_amount
                } else {
                    a_to_b_amount / b_to_a_amount
                };
                
                if ratio > self.config.wash_trade_threshold {
                    let mut related_txs = Vec::new();
                    related_txs.extend(a_to_b_txs);
                    related_txs.extend(b_to_a_txs);
                    let severity = (10.0 * ratio).min(10.0) as u8;
                    
                    self.anomalies.push(AnomalyReport {
                        anomaly_type: AnomalyType::WashTrading,
                        severity,
                        description: format!(
                            "Potential wash trading between {} and {} with {:.2}% of value returning",
                            addr1, addr2, ratio * 100.0
                        ),
                        related_transactions: related_txs,
                        related_addresses: vec![addr1, addr2],
                        detection_time: Utc::now(),
                    });
                }
            }
        }
    }

    fn detect_circular_transactions(&mut self) {
        let mut graph: HashMap<String, Vec<(String, String, DateTime<Utc>)>> = HashMap::new();
        
        for tx in &self.transactions {
            graph.entry(tx.from_address.clone())
                .or_default()
                .push((tx.to_address.clone(), tx.tx_id.clone(), tx.timestamp));
        }
        
        for start_address in self.wallet_profiles.keys() {
            let mut visited = HashSet::new();
            let mut path = Vec::new();
            let mut tx_path = Vec::new();
            self.dfs_find_cycles(start_address, start_address, &graph, &mut visited, &mut path, &mut tx_path, 0);
        }
    }

    fn dfs_find_cycles(
        &mut self,
        start_address: &str,
        current_address: &str,
        graph: &HashMap<String, Vec<(String, String, DateTime<Utc>)>>,
        visited: &mut HashSet<String>,
        path: &mut Vec<String>,
        tx_path: &mut Vec<String>,
        depth: usize,
    ) {
        path.push(current_address.to_string());
        visited.insert(current_address.to_string());
        
        if depth >= self.config.circular_depth_search {
            visited.remove(current_address);
            path.pop();
            return;
        }
        
        if let Some(neighbors) = graph.get(current_address) {
            for (next_address, tx_id, _) in neighbors {
                if next_address == start_address && path.len() > 2 {
                    let mut cycle_tx_ids = tx_path.clone();
                    cycle_tx_ids.push(tx_id.clone());
                    let mut cycle_addresses = path.clone();
                    cycle_addresses.push(start_address.to_string());
                    
                    self.anomalies.push(AnomalyReport {
                        anomaly_type: AnomalyType::CircularTransaction,
                        severity: ((path.len() as f64 / 2.0) as u8).min(10),
                        description: format!("Detected circular transaction pattern with {} addresses", path.len() + 1),
                        related_transactions: cycle_tx_ids,
                        related_addresses: cycle_addresses,
                        detection_time: Utc::now(),
                    });
                } else if !visited.contains(next_address) {
                    tx_path.push(tx_id.clone());
                    self.dfs_find_cycles(start_address, next_address, graph, visited, path, tx_path, depth + 1);
                    tx_path.pop();
                }
            }
        }
        
        visited.remove(current_address);
        path.pop();
    }

    fn detect_structured_transactions(&mut self) {
        let mut sender_txs: HashMap<String, Vec<Transaction>> = HashMap::new();
        
        for tx in &self.transactions {
            sender_txs.entry(tx.from_address.clone()).or_default().push(tx.clone());
        }
        
        for (sender, transactions) in sender_txs {
            if transactions.len() < 3 { continue; }
            
            let mut sorted_txs = transactions;
            sorted_txs.sort_by(|a, b| a.timestamp.cmp(&b.timestamp));
            
            let mut time_clusters: Vec<Vec<Transaction>> = Vec::new();
            let mut current_cluster = vec![sorted_txs[0].clone()];
            let mut prev_time = sorted_txs[0].timestamp;
            
            for tx in &sorted_txs[1..] {
                let time_diff = tx.timestamp.signed_duration_since(prev_time);
                if time_diff.num_seconds() as u64 <= self.config.transaction_time_window.as_secs() {
                    current_cluster.push(tx.clone());
                } else {
                    if current_cluster.len() >= 1 {
                        time_clusters.push(current_cluster);
                    }
                    current_cluster = vec![tx.clone()];
                }
                prev_time = tx.timestamp;
            }
            if !current_cluster.is_empty() {
                time_clusters.push(current_cluster);
            }
            
            for cluster in time_clusters {
                if cluster.len() < 3 { continue; }
                
                let mut total_amount = 0.0;
                let mut similar_amounts = true;
                let base_amount = cluster[0].amount;
                
                for tx in &cluster {
                    total_amount += tx.amount;
                    let ratio = if tx.amount > base_amount { base_amount / tx.amount } else { tx.amount / base_amount };
                    if ratio < self.config.structuring_threshold {
                        similar_amounts = false;
                    }
                }
                
                let is_round_number = (total_amount / 1000.0).round() * 1000.0 - total_amount < 0.05 * total_amount;
                
                if similar_amounts || is_round_number {
                    let tx_ids: Vec<String> = cluster.iter().map(|tx| tx.tx_id.clone()).collect();
                    let unique_recipients: HashSet<String> = cluster.iter().map(|tx| tx.to_address.clone()).collect();
                    let mut related_addresses = vec![sender.clone()];
                    related_addresses.extend(unique_recipients);
                    
                    let severity = if similar_amounts && is_round_number { 9 } else if similar_amounts { 7 } else { 5 };
                    
                    self.anomalies.push(AnomalyReport {
                        anomaly_type: AnomalyType::StructuredTransactions,
                        severity,
                        description: format!(
                            "Potential structuring: {} transactions within short time window, {}total: {:.2}",
                            cluster.len(), if is_round_number { "round " } else { "" }, total_amount
                        ),
                        related_transactions: tx_ids,
                        related_addresses,
                        detection_time: Utc::now(),
                    });
                }
            }
        }
    }

    fn detect_unusual_volume(&mut self) {
        let mut daily_volumes: HashMap<String, HashMap<String, f64>> = HashMap::new();
        
        for tx in &self.transactions {
            let date_str = tx.timestamp.format("%Y-%m-%d").to_string();
            daily_volumes.entry(tx.from_address.clone()).or_default()
                .entry(date_str.clone()).and_modify(|vol| *vol += tx.amount).or_insert(tx.amount);
            daily_volumes.entry(tx.to_address.clone()).or_default()
                .entry(date_str).and_modify(|vol| *vol += tx.amount).or_insert(tx.amount);
        }
        
        let cutoff_date = Utc::now() - chrono::Duration::days(self.config.volume_baseline_days as i64);
        for (address, daily_vol) in &daily_volumes {
            let relevant_volumes: Vec<f64> = daily_vol.iter()
                .filter(|(date, _)| {
                    let tx_date = DateTime::parse_from_str(&format!("{} 00:00:00 +0000", date), "%Y-%m-%d %H:%M:%S %z")
                        .unwrap().with_timezone(&Utc);
                    tx_date >= cutoff_date
                })
                .map(|(_, vol)| *vol)
                .collect();
            let avg_volume = if !relevant_volumes.is_empty() {
                relevant_volumes.iter().sum::<f64>() / relevant_volumes.len() as f64
            } else { 1.0 };
            
            for (date, volume) in daily_vol {
                if *volume > avg_volume * self.config.unusual_volume_factor {
                    let date_start = DateTime::parse_from_str(&format!("{} 00:00:00 +0000", date), "%Y-%m-%d %H:%M:%S %z")
                        .unwrap().with_timezone(&Utc);
                    let date_end = date_start + chrono::Duration::days(1);
                    
                    let related_txs: Vec<String> = self.transactions.iter()
                        .filter(|tx| (tx.from_address == *address || tx.to_address == *address) &&
                                tx.timestamp >= date_start && tx.timestamp < date_end)
                        .map(|tx| tx.tx_id.clone())
                        .collect();
                    
                    if !related_txs.is_empty() {
                        let ratio = volume / avg_volume;
                        let severity = (ratio / self.config.unusual_volume_factor * 5.0).min(10.0) as u8;
                        
                        self.anomalies.push(AnomalyReport {
                            anomaly_type: AnomalyType::UnusualVolume,
                            severity,
                            description: format!(
                                "Unusual volume for {} on {}: {:.2}x higher than average",
                                address, date, ratio
                            ),
                            related_transactions: related_txs,
                            related_addresses: vec![address.clone()],
                            detection_time: Utc::now(),
                        });
                    }
                }
            }
        }
    }

    fn detect_address_clustering(&mut self) {
        let mut address_clusters: HashMap<String, HashSet<String>> = HashMap::new();
        
        for address in self.wallet_profiles.keys() {
            let mut cluster = HashSet::new();
            cluster.insert(address.clone());
            address_clusters.insert(address.clone(), cluster);
        }
        
        for tx in &self.transactions {
            if let (Some(from_cluster), Some(to_cluster)) = (
                address_clusters.remove(&tx.from_address),
                address_clusters.remove(&tx.to_address)
            ) {
                let merged_cluster: HashSet<String> = from_cluster.union(&to_cluster).cloned().collect();
                for address in &merged_cluster {
                    address_clusters.insert(address.clone(), merged_cluster.clone());
                }
            }
        }
        
        let mut unique_clusters: Vec<HashSet<String>> = Vec::new();
        let mut processed_addresses: HashSet<String> = HashSet::new();
        for (address, cluster) in &address_clusters {
            if !processed_addresses.contains(address) {
                unique_clusters.push(cluster.clone());
                processed_addresses.extend(cluster.iter().cloned());
            }
        }
        
        for cluster in unique_clusters {
            if cluster.len() >= self.config.min_cluster_size {
                let cluster_txs: Vec<String> = self.transactions.iter()
                    .filter(|tx| cluster.contains(&tx.from_address) && cluster.contains(&tx.to_address))
                    .map(|tx| tx.tx_id.clone())
                    .collect();
                
                if !cluster_txs.is_empty() {
                    let internal_tx_ratio = cluster_txs.len() as f64 / cluster.len() as f64;
                    let severity = ((internal_tx_ratio * 2.0) + (cluster.len() as f64 / 5.0)).min(10.0) as u8;
                    
                    self.anomalies.push(AnomalyReport {
                        anomaly_type: AnomalyType::AddressClustering,
                        severity,
                        description: format!(
                            "Detected cluster of {} addresses with high internal transaction volume",
                            cluster.len()
                        ),
                        related_transactions: cluster_txs,
                        related_addresses: cluster.into_iter().collect(),
                        detection_time: Utc::now(),
                    });
                }
            }
        }
    }

    fn detect_suspicious_new_wallets(&mut self) {
        for (address, profile) in &self.wallet_profiles {
            let wallet_age = Utc::now().signed_duration_since(profile.first_seen).num_days();
            if wallet_age <= 7 && profile.transaction_count >= 10 {
                let related_txs: Vec<String> = self.transactions.iter()
                    .filter(|tx| tx.from_address == *address || tx.to_address == *address)
                    .map(|tx| tx.tx_id.clone())
                    .collect();
                
                let severity = ((profile.transaction_count as f64 / wallet_age.max(1) as f64) / 2.0).min(10.0) as u8;
                
                self.anomalies.push(AnomalyReport {
                    anomaly_type: AnomalyType::SuspiciousNewWallet,
                    severity,
                    description: format!(
                        "New wallet ({} days old) with high activity ({} transactions)",
                        wallet_age, profile.transaction_count
                    ),
                    related_transactions: related_txs,
                    related_addresses: vec![address.clone()],
                    detection_time: Utc::now(),
                });
            }
        }
    }

    fn detect_transaction_spikes(&mut self) {
        let mut hourly_counts: HashMap<String, usize> = HashMap::new();
        
        for tx in &self.transactions {
            let hour_str = tx.timestamp.format("%Y-%m-%d %H").to_string();
            *hourly_counts.entry(hour_str).or_insert(0) += 1;
        }
        
        let counts: Vec<usize> = hourly_counts.values().cloned().collect();
        let average = if counts.is_empty() { 0.0 } else { counts.iter().sum::<usize>() as f64 / counts.len() as f64 };
        let variance = if counts.is_empty() { 0.0 } else {
            counts.iter().map(|&c| (c as f64 - average).powi(2)).sum::<f64>() / counts.len() as f64
        };
        let std_dev = variance.sqrt();
        let threshold = average + 3.0 * std_dev;
        
        for (hour, count) in &hourly_counts {
            if *count as f64 > threshold {
                let hour_start = DateTime::parse_from_str(&format!("{} 00:00 +0000", hour), "%Y-%m-%d %H %M %z")
                    .unwrap().with_timezone(&Utc);
                let hour_end = hour_start + chrono::Duration::hours(1);
                
                let related_txs: Vec<String> = self.transactions.iter()
                    .filter(|tx| tx.timestamp >= hour_start && tx.timestamp < hour_end)
                    .map(|tx| tx.tx_id.clone())
                    .collect();
                
                let related_addresses: HashSet<String> = self.transactions.iter()
                    .filter(|tx| tx.timestamp >= hour_start && tx.timestamp < hour_end)
                    .flat_map(|tx| vec![tx.from_address.clone(), tx.to_address.clone()])
                    .collect();
                
                let std_devs_above = (*count as f64 - average) / std_dev;
                let severity = (std_devs_above / 2.0).min(10.0) as u8;
                
                self.anomalies.push(AnomalyReport {
                    anomaly_type: AnomalyType::TransactionSpike,
                    severity,
                    description: format!(
                        "Transaction spike at {}: {} txs ({:.1}x above average)",
                        hour, count, *count as f64 / average
                    ),
                    related_transactions: related_txs,
                    related_addresses: related_addresses.into_iter().collect(),
                    detection_time: Utc::now(),
                });
            }
        }
    }

    fn export_anomalies<P: AsRef<Path>>(&self, path: P) -> Result<(), Box<dyn Error>> {
        let file = File::create(path)?;
        serde_json::to_writer_pretty(file, &self.anomalies)?;
        Ok(())
    }

    fn get_high_risk_anomalies(&self, min_severity: u8) -> Vec<&AnomalyReport> {
        self.anomalies.iter().filter(|a| a.severity >= min_severity).collect()
    }

    fn get_anomalies_by_type(&self, anomaly_type: AnomalyType) -> Vec<&AnomalyReport> {
        self.anomalies.iter().filter(|a| a.anomaly_type == anomaly_type).collect()
    }
}

// Sample data generator for testing
fn generate_sample_transactions(count: usize) -> Vec<Transaction> {
    let mut rng = rand::thread_rng();
    let mut transactions = Vec::new();
    
    for i in 0..count {
        let tx_id = format!("tx{}", i);
        let timestamp = Utc::now() - chrono::Duration::days(rng.gen_range(0..30));
        let from_address = format!("addr{}", rng.gen_range(0..10));
        let to_address = format!("addr{}", rng.gen_range(0..10));
        let amount = rng.gen_range(0.1..1000.0);
        let fee = rng.gen_range(0.001..0.1);
        let currency = "BTC".to_string();
        
        transactions.push(Transaction {
            tx_id,
            timestamp,
            from_address,
            to_address,
            amount,
            fee,
            currency,
        });
    }
    
    transactions
}

fn main() -> Result<(), Box<dyn Error>> {
    println!("Blockchain Anomaly Detector");
    
    let config = AnalyzerConfig {
        wash_trade_threshold: 0.8,
        circular_depth_search: 5,
        unusual_volume_factor: 3.0,
        structuring_threshold: 0.9,
        transaction_time_window: Duration::from_secs(3600),
        min_cluster_size: 3,
        volume_baseline_days: 30,
    };
    
    let mut analyzer = BlockchainAnalyzer::new(config);
    
    // Uncomment the following lines to test with sample data instead of a file
    /*
    println!("Generating sample transaction data...");
    analyzer.transactions = generate_sample_transactions(1000);
    println!("Generated {} transactions", analyzer.transactions.len());
    */
    
    // Load transaction data from file (comment out if using sample data)
    println!("Loading transaction data...");
    analyzer.load_transactions_from_file("transactions.json")?;
    println!("Loaded {} transactions", analyzer.transactions.len());
    
    println!("Building wallet profiles...");
    analyzer.build_wallet_profiles();
    println!("Created profiles for {} wallets", analyzer.wallet_profiles.len());
    
    println!("Detecting anomalies...");
    analyzer.detect_anomalies();
    println!("Detected {} anomalies", analyzer.anomalies.len());
    
    println!("Exporting anomaly report...");
    analyzer.export_anomalies("anomalies.json")?;
    
    println!("\nANOMALY DETECTION SUMMARY");
    println!("=========================");
    println!("High Risk Anomalies (Severity >= 8): {}", 
             analyzer.get_high_risk_anomalies(8).len());
    
    println!("\nAnomalies by Type:");
    for anomaly_type in [
        AnomalyType::WashTrading, AnomalyType::CircularTransaction, AnomalyType::StructuredTransactions,
        AnomalyType::UnusualVolume, AnomalyType::AddressClustering, AnomalyType::SuspiciousNewWallet,
        AnomalyType::TransactionSpike
    ] {
        println!("  - {:?}: {}", anomaly_type, analyzer.get_anomalies_by_type(anomaly_type).len());
    }
    
    println!("\nExported full report to anomalies.json");
    Ok(())
}