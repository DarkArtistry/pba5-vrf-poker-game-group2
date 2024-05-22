use schnorrkel::{Keypair, MiniSecretKey, PublicKey, Signature, signing_context, vrf::{VRFInOut, VRFProof}};
use rand::rngs::OsRng;
use std::collections::HashMap;

const CONTEXT: &[u8] = b"example";

#[derive(Debug)]
struct Player {
    keypair: Keypair,
    vrf_output: Option<VRFInOut>,
    vrf_proof: Option<VRFProof>,
}

impl Player {
    fn new() -> Self {
        let keypair = Keypair::generate_with(OsRng);
        Player {
            keypair,
            vrf_output: None,
            vrf_proof: None,
        }
    }

    fn draw_card(&mut self, input: &[u8]) {
        let (inout, proof, _) = self.keypair.vrf_sign(signing_context(CONTEXT).bytes(input));
        self.vrf_output = Some(inout);
        self.vrf_proof = Some(proof);
    }

    fn reveal_card(&self) -> Option<u8> {
        self.vrf_output.as_ref().and_then(|output| {
            let hash: Vec<u8> = output.output.to_bytes().to_vec();
            if hash.len() < 8 {
                return None;
            }
            let card_value = u64::from_le_bytes(hash[0..8].try_into().unwrap()) % 52;
            Some(card_value as u8)
        })
    }
    
    fn verify_card(&self, input: &[u8]) -> bool {
        if let (Some(output), Some(proof)) = (&self.vrf_output, &self.vrf_proof) {
            self.keypair
                .public
                .vrf_verify(signing_context(CONTEXT).bytes(input), &output.to_preout(), proof)
                .is_ok()
        } else {
            false
        }
    }
}

fn main() {
    let mut players: HashMap<&str, Player> = HashMap::new();
    players.insert("Alice", Player::new());
    players.insert("Bob", Player::new());


    for round in 1..=10 {
        println!("Round {}", round);
    
        // Commit-reveal phase
        let commit_string = format!("poker_game{}", round);
        let commit_input = commit_string.as_bytes();
    
        // Players draw their cards
        for player in players.values_mut() {
            player.draw_card(commit_input);
        }
    
        // Reveal phase
        for (name, player) in &players {
            if let Some(card) = player.reveal_card() {
                println!("{}'s card: {}", name, card);
            } else {
                println!("{} has not drawn a card.", name);
            }
        }
    
        // Verify the cards
        for (name, player) in &players {
            let is_valid = player.verify_card(commit_input);
            println!("{}'s card is valid: {}", name, is_valid);
        }

        let winner = players.iter().max_by_key(|&(_, player)| player.reveal_card().unwrap_or(0));
        if let Some((name, _)) = winner {
            println!("{} wins!", name);
        }
    }
}


#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_new_player() {
        let player = Player::new();
        assert!(player.vrf_output.is_none());
        assert!(player.vrf_proof.is_none());
    }

    #[test]
    fn test_draw_card() {
        let mut player = Player::new();
        player.draw_card(b"test");
        assert!(player.vrf_output.is_some());
        assert!(player.vrf_proof.is_some());
    }

    #[test]
    fn test_reveal_card() {
        let mut player = Player::new();
        player.draw_card(b"test");
        let card = player.reveal_card();
        assert!(card.is_some());
        assert!(card.unwrap() < 52);
    }

    #[test]
    fn test_verify_card() {
        let mut player = Player::new();
        player.draw_card(b"test");
        let is_valid = player.verify_card(b"test");
        assert!(is_valid);
    }

    #[test]
    fn test_verify_card_with_wrong_input() {
        let mut player = Player::new();
        player.draw_card(b"test");
        let is_valid = player.verify_card(b"wrong");
        assert!(!is_valid);
    }
}