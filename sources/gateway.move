module gateway::gateway {
    use std::signer;
    use std::vector;
    use std::option;
    use std::simple_map::{Self, SimpleMap};
    use std::string::{Self, String};
    use aptos_framework::event::{Self, EventHandle, emit_event};
    use aptos_framework::account;
    use aptos_framework::fungible_asset;
    use aptos_framework::primary_fungible_store;
    use aptos_framework::object;
    use std::hash;
    use aptos_std::debug::print;
    use aptos_framework::bcs;
    use aptos_framework::timestamp;

    // Constants
    const SEED: vector<u8> = b"GATEWAY_SEED"; // Seed for resource account creation
    const MAX_BPS: u64 = 100000; // Maximum basis points (100%) for fee calculations
    const TOKEN_BASE: u64 = 1000000;
    const BASE_BPS: u64 = 1000;
    const TOKEN_BASE_TENTH: u64 = 100000;
    const BASE_BPS_TENTH: u64 = 100;
    const E_ZERO_ADDRESS: u64 = 1;
    const E_TOKEN_NOT_SUPPORTED: u64 = 2;
    const E_AMOUNT_ZERO: u64 = 3;
    const E_INVALID_STATUS: u64 = 4;
    const E_ALREADY_INITIALIZED: u64 = 5;
    const E_NOT_OWNER: u64 = 6;
    const E_NOT_AGGREGATOR: u64 = 7;
    const E_ORDER_FULFILLED: u64 = 8;
    const E_ORDER_REFUNDED: u64 = 9;
    const E_FEE_EXCEEDS_PROTOCOL: u64 = 10;
    const E_PAUSED: u64 = 11;
    const E_NOT_PAUSED: u64 = 12;
    const E_INVALID_MESSAGE_HASH: u64 = 13;
    const E_ORDER_NOT_FOUND: u64 = 14;
    const E_TOKEN_NOT_FOUND: u64 = 15;
    const E_PROTOCOL_FEE_SAME: u64 = 15;

    // Store the resource account signer capability
    struct SignerCapabilityStore has key {
        signer_cap: account::SignerCapability,
    }

    struct GatewaySettings has key {
        owner: address,
        pending_owner: address,
        aggregator_address: address,
        treasury_address: address,
        protocol_fee_percent: u64,
        paused: bool,
        supported_tokens: vector<address>,
        order_store: vector<Order>,
        order_store_map: SimpleMap<vector<u8>, u64>,
        order_created_events: EventHandle<OrderCreatedEvent>,
        order_settled_events: EventHandle<OrderSettledEvent>,
        order_refunded_events: EventHandle<OrderRefundedEvent>,
        sender_fee_transferred_events: EventHandle<SenderFeeTransferredEvent>,
        protocol_fee_updated_events: EventHandle<ProtocolFeeUpdatedEvent>,
        protocol_address_updated_events: EventHandle<ProtocolAddressUpdatedEvent>,
        protocol_token_address_updated_events: EventHandle<ProtocolTokenAddressUpdatedEvent>,
    }

    struct Order has store, drop, copy {
        sender: address,
        token: address,
        sender_fee_recipient: address,
        sender_fee: u64,
        protocol_fee: u64,
        is_fulfilled: bool,
        is_refunded: bool,
        refund_address: address,
        current_bps: u64,
        amount: u64,
        order_id: vector<u8>,
        nonce: u64,
    }

    struct OrderCreatedEvent has drop, store {
        sender: address,
        token: address,
        amount: u64,
        protocol_fee: u64,
        order_id: vector<u8>,
        rate: u64,
        message_hash: String,
    }

    struct OrderSettledEvent has drop, store {
        split_order_id: vector<u8>,
        order_id: vector<u8>,
        liquidity_provider: address,
        settle_percent: u64,
    }

    struct OrderRefundedEvent has drop, store {
        fee: u64,
        order_id: vector<u8>,
    }

    struct SenderFeeTransferredEvent has drop, store {
        sender: address,
        amount: u64,
    }

    struct ProtocolFeeUpdatedEvent has drop, store {
        protocol_fee: u64,
    }

    struct ProtocolAddressUpdatedEvent has drop, store {
        what: String,
        new_address: address,
    }

    struct ProtocolTokenAddressUpdatedEvent has drop, store {
        what: String,
        value: address,
        status: u64,
    }

    // Initializes the Gateway contract with resource account
    fun init_module(account: &signer) {
        let sender_addr = signer::address_of(account);

        // Create resource account
        let (resource_signer, signer_cap) = account::create_resource_account(account, SEED);
        let settings = GatewaySettings {
            owner: sender_addr,
            pending_owner: @0x0,
            aggregator_address: @0x0,
            treasury_address: @0x0,
            protocol_fee_percent: 0,
            paused: false,
            supported_tokens: vector::empty(),
            order_store: vector::empty(),
            order_store_map: simple_map::new(),
            order_created_events: account::new_event_handle<OrderCreatedEvent>(&resource_signer),
            order_settled_events: account::new_event_handle<OrderSettledEvent>(&resource_signer),
            order_refunded_events: account::new_event_handle<OrderRefundedEvent>(&resource_signer),
            sender_fee_transferred_events: account::new_event_handle<SenderFeeTransferredEvent>(&resource_signer),
            protocol_fee_updated_events: account::new_event_handle<ProtocolFeeUpdatedEvent>(&resource_signer),
            protocol_address_updated_events: account::new_event_handle<ProtocolAddressUpdatedEvent>(&resource_signer),
            protocol_token_address_updated_events: account::new_event_handle<ProtocolTokenAddressUpdatedEvent>(&resource_signer),
        };

        move_to(&resource_signer, settings);
        move_to(account, SignerCapabilityStore { signer_cap });
    }

    // Adds or removes a token from the supported list (owner only)
    public entry fun setting_manager_bool(
        account: &signer,
        what: String,
        value: address,
        status: u64
    ) acquires GatewaySettings {
        let deployer_addr = signer::address_of(account);
        let resource_addr = get_resource_address(deployer_addr);
        assert_is_owner(resource_addr);
        let settings = borrow_global_mut<GatewaySettings>(resource_addr);
        assert_not_zero_address(value);
        assert_valid_status(status);

        if (what == string::utf8(b"token")) {
            if (status == 1 && !vector::contains(&settings.supported_tokens, &value)) {
                vector::push_back(&mut settings.supported_tokens, value);
            } else if (status == 2) {
                let (found, idx) = vector::index_of(&settings.supported_tokens, &value);
                if (found) {
                    vector::remove(&mut settings.supported_tokens, idx);
                } else {
                    abort E_TOKEN_NOT_FOUND;
                };
            };
            emit_event(&mut settings.protocol_token_address_updated_events, ProtocolTokenAddressUpdatedEvent {
                what,
                value,
                status,
            });
        }
    }

    // Updates the protocol fee percentage (owner only)
    public entry fun update_protocol_fee(account: &signer, protocol_fee_percent: u64) acquires GatewaySettings {
        let deployer_addr = signer::address_of(account);
        let resource_addr = get_resource_address(deployer_addr);
        assert_is_owner(resource_addr);
        let settings = borrow_global_mut<GatewaySettings>(resource_addr);
        settings.protocol_fee_percent = (protocol_fee_percent * BASE_BPS_TENTH);
        emit_event(&mut settings.protocol_fee_updated_events, ProtocolFeeUpdatedEvent {
            protocol_fee: protocol_fee_percent,
        });
    }

    // Updates the treasury or aggregator address (owner only)
    public entry fun update_protocol_address(account: &signer, what: String, value: address) acquires GatewaySettings {
        let deployer_addr = signer::address_of(account);
        let resource_addr = get_resource_address(deployer_addr);
        assert_is_owner(resource_addr);
        let settings = borrow_global_mut<GatewaySettings>(resource_addr);
        assert_not_zero_address(value);

        if (what == string::utf8(b"treasury")) {
            settings.treasury_address = value;
            emit_event(&mut settings.protocol_address_updated_events, ProtocolAddressUpdatedEvent {
                what,
                new_address: value,
            });
        } else if (what == string::utf8(b"aggregator")) {
            settings.aggregator_address = value;
            emit_event(&mut settings.protocol_address_updated_events, ProtocolAddressUpdatedEvent {
                what,
                new_address: value,
            });
        };
    }

    // Pauses the contract (owner only)
    public entry fun pause(account: &signer) acquires GatewaySettings {
        let deployer_addr = signer::address_of(account);
        let resource_addr = get_resource_address(deployer_addr);
        assert_is_owner(resource_addr);
        let settings = borrow_global_mut<GatewaySettings>(resource_addr);
        assert_not_paused(settings);
        settings.paused = true;
    }

    // Unpauses the contract (owner only)
    public entry fun unpause(account: &signer) acquires GatewaySettings {
        let deployer_addr = signer::address_of(account);
        let resource_addr = get_resource_address(deployer_addr);
        assert_is_owner(resource_addr);
        let settings = borrow_global_mut<GatewaySettings>(resource_addr);
        assert_paused(settings);
        settings.paused = false;
    }

    public entry fun create_order(
        account: &signer,
        token: address,
        amount: u64,
        rate: u64,
        sender_fee_recipient: address,
        sender_fee: u64,
        refund_address: address,
        message_hash: String
    ) acquires GatewaySettings {
        let deployer_addr = @gateway;
        let resource_addr = get_resource_address(deployer_addr);
        let settings = borrow_global_mut<GatewaySettings>(resource_addr);
        assert_not_paused(settings);
        assert_token_supported(settings, token);
        assert_amount_not_zero(amount);
        assert_not_zero_address(refund_address);
        assert_not_zero_address(settings.treasury_address);
        assert_not_zero_address(settings.aggregator_address);
        if (sender_fee != 0) assert_not_zero_address(sender_fee_recipient);
        assert_valid_message_hash(&message_hash);

        let sender_addr = signer::address_of(account);
        let addr_bytes = bcs::to_bytes(&sender_addr);
        let timestamp = timestamp::now_microseconds();
        let nonce_bytes = bcs::to_bytes(&timestamp);
        vector::append(&mut addr_bytes, nonce_bytes);
        let order_id = hash::sha3_256(addr_bytes);
        let protocol_fee = (amount * settings.protocol_fee_percent) / (MAX_BPS + settings.protocol_fee_percent);
        let order_amount = amount - protocol_fee;

        let order = Order {
            sender: sender_addr,
            token,
            sender_fee_recipient,
            sender_fee: (sender_fee * TOKEN_BASE_TENTH),
            protocol_fee: (protocol_fee * TOKEN_BASE_TENTH),
            is_fulfilled: false,
            is_refunded: false,
            refund_address,
            current_bps: MAX_BPS,
            amount: (order_amount * TOKEN_BASE_TENTH),
            order_id,
            nonce: timestamp,
        };
        vector::push_back(&mut settings.order_store, order);
        let (found, i) = vector::index_of(&settings.order_store, &order);
        assert!(found, E_ORDER_NOT_FOUND);
        simple_map::add(&mut settings.order_store_map, order_id, i);

        let usdc_metadata = object::address_to_object<fungible_asset::Metadata>(token);
        let total_amount = amount + sender_fee; // Input amount and sender_fee are *10 values
        // Transfer tokens to resource_addr
        primary_fungible_store::transfer(account, usdc_metadata, resource_addr, (total_amount * TOKEN_BASE_TENTH));

        emit_event(&mut settings.order_created_events, OrderCreatedEvent {
            sender: sender_addr,
            token,
            amount: (order_amount * TOKEN_BASE_TENTH),
            protocol_fee: (protocol_fee * TOKEN_BASE_TENTH),
            order_id,
            rate,
            message_hash,
        });
    }

    // Settles an order partially or fully (aggregator only)
    public entry fun settle(
        account: &signer,
        split_order_id: vector<u8>,
        order_id: vector<u8>,
        liquidity_provider: address,
        settle_percent: u64
    ) acquires GatewaySettings, SignerCapabilityStore {
        let deployer_addr = @gateway;
        let resource_addr = get_resource_address(deployer_addr);
        let settings = borrow_global_mut<GatewaySettings>(resource_addr);
        assert_is_aggregator(settings, signer::address_of(account));
        let idx = *simple_map::borrow(&settings.order_store_map, &order_id);
        let order = vector::borrow_mut(&mut settings.order_store, idx);
        let signer_cap_store = borrow_global<SignerCapabilityStore>(@gateway);

        let resource_signer = account::create_signer_with_capability(&signer_cap_store.signer_cap);

        assert_order_not_fulfilled(order);
        assert_order_not_refunded(order);

        assert!((settle_percent * BASE_BPS) <= order.current_bps, 200);

        order.current_bps = order.current_bps - (settle_percent * BASE_BPS);

        let liquidity_provider_amount = (order.amount * (settle_percent * BASE_BPS)) / MAX_BPS;
        order.amount = order.amount - liquidity_provider_amount;

        let usdc_metadata = object::address_to_object<fungible_asset::Metadata>(order.token);

        if (order.current_bps == 0) {
            order.is_fulfilled = true;
            if (order.sender_fee != 0) {
                primary_fungible_store::transfer(&resource_signer, usdc_metadata, order.sender_fee_recipient, order.sender_fee);
                emit_event(&mut settings.sender_fee_transferred_events, SenderFeeTransferredEvent {
                    sender: order.sender_fee_recipient,
                    amount: order.sender_fee,
                });
            };
            if (order.protocol_fee != 0) {
                primary_fungible_store::transfer(&resource_signer, usdc_metadata, settings.treasury_address, order.protocol_fee);
            };
        };

        primary_fungible_store::transfer(&resource_signer, usdc_metadata, liquidity_provider, liquidity_provider_amount);

        emit_event(&mut settings.order_settled_events, OrderSettledEvent {
            split_order_id,
            order_id,
            liquidity_provider,
            settle_percent,
        });
    }

    // Refunds an order (aggregator only)
    public entry fun refund(
        account: &signer,
        fee: u64,
        order_id: vector<u8>
    ) acquires GatewaySettings, SignerCapabilityStore {
        let deployer_addr = @gateway;
        let resource_addr = get_resource_address(deployer_addr);
        let settings = borrow_global_mut<GatewaySettings>(resource_addr);
        assert_is_aggregator(settings, signer::address_of(account));
        let idx = *simple_map::borrow(&settings.order_store_map, &order_id);
        let order = vector::borrow_mut(&mut settings.order_store, idx);
        assert_order_not_fulfilled(order);
        assert_order_not_refunded(order);
        assert_fee_not_exceeds_protocol(order, fee);

        let signer_cap_store = borrow_global<SignerCapabilityStore>(@gateway);

        let resource_signer = account::create_signer_with_capability(&signer_cap_store.signer_cap);

        let usdc_metadata = object::address_to_object<fungible_asset::Metadata>(order.token);

        if (fee != 0) {
            primary_fungible_store::transfer(&resource_signer, usdc_metadata, settings.treasury_address, (fee * TOKEN_BASE_TENTH));
        };

        order.is_refunded = true;
        order.current_bps = 0;
        let refund_amount = order.amount + order.protocol_fee - (fee * TOKEN_BASE_TENTH);

        primary_fungible_store::transfer(&resource_signer, usdc_metadata, order.refund_address, refund_amount + order.sender_fee);

        emit_event(&mut settings.order_refunded_events, OrderRefundedEvent {
            fee,
            order_id,
        });
    }

    /*  --------------------------------------------------------------------------------------------
   Helper Functions
    ------------------------------------------------------------------------------------------------*/
    // This are the assert function

    // Inline helper functions for assertions
    inline fun assert_not_zero_address(addr: address) {
        assert!(addr != @0x0, E_ZERO_ADDRESS);
    }

    inline fun assert_token_supported(settings: &GatewaySettings, token: address) {
        assert!(vector::contains(&settings.supported_tokens, &token), E_TOKEN_NOT_SUPPORTED);
    }

    inline fun assert_amount_not_zero(amount: u64) {
        assert!(amount != 0, E_AMOUNT_ZERO);
    }

    inline fun assert_valid_status(status: u64) {
        assert!(status == 1 || status == 2, E_INVALID_STATUS);
    }

    inline fun assert_not_already_initialized(deployer_addr: address) {
        let resource_addr = get_resource_address(deployer_addr);
        assert!(!exists<GatewaySettings>(resource_addr), E_ALREADY_INITIALIZED);
    }

    inline fun assert_is_owner( sender: address) {
        assert!(exists<GatewaySettings>(sender), E_NOT_OWNER);
    }

    inline fun assert_is_aggregator(settings: &GatewaySettings, sender: address) {
        assert!(settings.aggregator_address == sender, E_NOT_AGGREGATOR);
    }

    inline fun assert_order_not_fulfilled(order: &Order) {
        assert!(!order.is_fulfilled, E_ORDER_FULFILLED);
    }

    inline fun assert_order_not_refunded(order: &Order) {
        assert!(!order.is_refunded, E_ORDER_REFUNDED);
    }

    inline fun assert_fee_not_exceeds_protocol(order: &Order, fee: u64) {
        assert!(order.protocol_fee >= fee, E_FEE_EXCEEDS_PROTOCOL);
    }

    inline fun assert_not_paused(settings: &GatewaySettings) {
        assert!(!settings.paused, E_PAUSED);
    }

    inline fun assert_paused(settings: &GatewaySettings) {
        assert!(settings.paused, E_NOT_PAUSED);
    }

    inline fun assert_valid_message_hash(message_hash: &String) {
        assert!(string::length(message_hash) > 0, E_INVALID_MESSAGE_HASH);
    }

    // helper function
    // Helper function to get resource account address
    fun get_resource_address(deployer_addr: address): address {
        account::create_resource_address(&deployer_addr, SEED)
    }

    /*  --------------------------------------------------------------------------------------------
    View Functions
    ------------------------------------------------------------------------------------------------*/

    // Checks if a token is supported
    #[view]
    public fun is_token_supported(token: address): bool acquires GatewaySettings {
        let resource_addr = get_resource_address(@gateway);
        let settings = borrow_global<GatewaySettings>(resource_addr);
        vector::contains(&settings.supported_tokens, &token)
    }

    // Retrieves order details
    #[view]
    public fun get_order_info(order_id: vector<u8>): Order acquires GatewaySettings {
        let resource_addr = get_resource_address(@gateway);
        let settings = borrow_global<GatewaySettings>(resource_addr);
        let idx = *simple_map::borrow(&settings.order_store_map, &order_id);
        *vector::borrow(&settings.order_store, idx)
    }

    // Retrieves fee details
    #[view]
    public fun get_fee_details(): (u64, u64) acquires GatewaySettings {
        let resource_addr = get_resource_address(@gateway);
        let settings = borrow_global<GatewaySettings>(resource_addr);
        (settings.protocol_fee_percent, MAX_BPS)
    }

    // Retrieves treasury address and aggregator address details
    #[view]
    public fun get_protocol_address(): (address, address) acquires GatewaySettings {
        let resource_addr = get_resource_address(@gateway);
        let settings = borrow_global<GatewaySettings>(resource_addr);
        (settings.treasury_address, settings.aggregator_address)
    }

    /* --------------------------------------------------------------------------------------------
    Test Functions for Edge cases
    ------------------------------------------------------------------------------------------------ */

    // Test functions
    #[test(account = @gateway)]
    fun test_init_module_success(account: &signer) acquires GatewaySettings, SignerCapabilityStore {
        let admin_address = signer::address_of(account);
        account::create_account_for_test(admin_address);

        let aptos_framework = account::create_account_for_test(@aptos_framework);
        timestamp::set_time_has_started_for_testing(&aptos_framework);

        init_module(account);

        let expected_resource_account_address = account::create_resource_address(&admin_address, SEED);

        assert!(exists<GatewaySettings>(expected_resource_account_address), 0);
        assert!(exists<SignerCapabilityStore>(admin_address), 0);

        let state = borrow_global<SignerCapabilityStore>(admin_address);
        let gateway = borrow_global<GatewaySettings>(expected_resource_account_address);
        assert!(
            account::get_signer_capability_address(&state.signer_cap) == expected_resource_account_address,
            0
        );

        assert!(event::counter(&gateway.order_created_events) == 0, 0);
        assert!(event::counter(&gateway.order_settled_events) == 0, 0);
        assert!(event::counter(&gateway.protocol_token_address_updated_events) == 0, 0);
        assert!(event::counter(&gateway.order_refunded_events) == 0, 0);
        assert!(event::counter(&gateway.protocol_address_updated_events) == 0, 0);
        assert!(event::counter(&gateway.sender_fee_transferred_events) == 0, 0);
        assert!(event::counter(&gateway.protocol_fee_updated_events) == 0, 0);
    }

    #[test(account = @gateway, test_user = @0x2)]
    #[expected_failure(abort_code = E_NOT_OWNER)]
    public fun test_setting_manager_bool_error_not_owner(
        account: &signer,
        test_user: &signer
    ) acquires GatewaySettings {
        let account_address = signer::address_of(account);
        let test_address = signer::address_of(test_user);
        account::create_account_for_test(account_address);
        account::create_account_for_test(test_address);

        // Set up timestamp for testing
        let aptos_framework = account::create_account_for_test(@aptos_framework);
        timestamp::set_time_has_started_for_testing(&aptos_framework);

        // Initialize the module
        init_module(account);

        let expected_resource_account_address = account::create_resource_address(&account_address, SEED);

        // set token address to test function
        let test_token_address = @0x3;
        // Get state BEFORE the function call
        let gateway_before = borrow_global<GatewaySettings>(expected_resource_account_address);
        let supported_tokens_before = vector::length(&gateway_before.supported_tokens);

        setting_manager_bool(test_user, string::utf8(b"token"), test_token_address, 1);

        let gateway_after = borrow_global<GatewaySettings>(expected_resource_account_address);
        let supported_tokens_after = vector::length(&gateway_after.supported_tokens);

        assert!(supported_tokens_before == supported_tokens_after, 0);

        assert!(event::counter(&gateway_after.protocol_token_address_updated_events) == 0, 0);
    }

    #[test(account = @gateway, test_user = @0x2)]
    #[expected_failure(abort_code = E_ZERO_ADDRESS)]
    public fun test_setting_manager_bool_error_zero_address(
        account: &signer,
        test_user: &signer
    ) acquires GatewaySettings {
        let account_address = signer::address_of(account);
        let test_address = signer::address_of(test_user);
        account::create_account_for_test(account_address);
        account::create_account_for_test(test_address);

        // Set up timestamp for testing
        let aptos_framework = account::create_account_for_test(@aptos_framework);
        timestamp::set_time_has_started_for_testing(&aptos_framework);

        // Initialize the module
        init_module(account);

        let expected_resource_account_address = account::create_resource_address(&account_address, SEED);

        // set token address to test function
        let test_token_address = @0x0;

        let gateway_before = borrow_global<GatewaySettings>(expected_resource_account_address);
        let supported_tokens_before = vector::length(&gateway_before.supported_tokens);

        setting_manager_bool(account, string::utf8(b"token"), test_token_address, 1);

        let gateway_after = borrow_global<GatewaySettings>(expected_resource_account_address);
        let supported_tokens_after = vector::length(&gateway_after.supported_tokens);

        assert!(supported_tokens_before == supported_tokens_after, 0);

        assert!(event::counter(&gateway_after.protocol_token_address_updated_events) == 0, 0);

    }

    #[test(account = @gateway, test_user = @0x2)]
    #[expected_failure(abort_code = E_INVALID_STATUS)]
    public fun test_setting_manager_bool_error_invalid_status(
        account: &signer,
        test_user: &signer
    ) acquires GatewaySettings {
        let account_address = signer::address_of(account);
        let test_address = signer::address_of(test_user);
        account::create_account_for_test(account_address);
        account::create_account_for_test(test_address);

        // Set up timestamp for testing
        let aptos_framework = account::create_account_for_test(@aptos_framework);
        timestamp::set_time_has_started_for_testing(&aptos_framework);

        // Initialize the module
        init_module(account);

        let expected_resource_account_address = account::create_resource_address(&account_address, SEED);

        // set token address to test function
        let test_token_address = @0x3;

        let gateway_before = borrow_global<GatewaySettings>(expected_resource_account_address);
        let supported_tokens_before = vector::length(&gateway_before.supported_tokens);

        setting_manager_bool(account, string::utf8(b"token"), test_token_address, 3);

        let gateway_after = borrow_global<GatewaySettings>(expected_resource_account_address);
        let supported_tokens_after = vector::length(&gateway_after.supported_tokens);

        assert!(supported_tokens_before == supported_tokens_after, 0);

        assert!(event::counter(&gateway_after.protocol_token_address_updated_events) == 0, 0);

    }

    #[test(account = @gateway, test_user = @0x2)]
    public fun test_setting_manager_bool_error_what_not_token(
        account: &signer,
        test_user: &signer
    ) acquires GatewaySettings {
        let account_address = signer::address_of(account);
        let test_address = signer::address_of(test_user);
        account::create_account_for_test(account_address);
        account::create_account_for_test(test_address);

        // Set up timestamp for testing
        let aptos_framework = account::create_account_for_test(@aptos_framework);
        timestamp::set_time_has_started_for_testing(&aptos_framework);

        // Initialize the module
        init_module(account);

        let expected_resource_account_address = account::create_resource_address(&account_address, SEED);
        let test_token_address = @0x3;

        // Get state BEFORE the function call
        let gateway_before = borrow_global<GatewaySettings>(expected_resource_account_address);
        let supported_tokens_before = vector::length(&gateway_before.supported_tokens);
        let event_count_before = event::counter(&gateway_before.protocol_token_address_updated_events);

        // Call the function that might modify state
        setting_manager_bool(account, string::utf8(b"treasury"), test_token_address, 1);

        // Get state AFTER the function call
        let gateway_after = borrow_global<GatewaySettings>(expected_resource_account_address);
        let supported_tokens_after = vector::length(&gateway_after.supported_tokens);
        let event_count_after = event::counter(&gateway_after.protocol_token_address_updated_events);

        // Compare before and after states
        assert!(supported_tokens_before == supported_tokens_after, 0);
        assert!(event_count_before == event_count_after, 0);
    }

    #[test(account = @gateway, test_user = @0x2)]
    public fun test_setting_manager_bool_success_status_1(
        account: &signer,
        test_user: &signer
    ) acquires GatewaySettings {
        let account_address = signer::address_of(account);
        let test_address = signer::address_of(test_user);
        account::create_account_for_test(account_address);
        account::create_account_for_test(test_address);

        // Set up timestamp for testing
        let aptos_framework = account::create_account_for_test(@aptos_framework);
        timestamp::set_time_has_started_for_testing(&aptos_framework);

        // Initialize the module
        init_module(account);

        let expected_resource_account_address = account::create_resource_address(&account_address, SEED);
        let test_token_address = @0x3;

        // Get state BEFORE the function call
        let gateway_before = borrow_global<GatewaySettings>(expected_resource_account_address);
        let supported_tokens_before = vector::length(&gateway_before.supported_tokens);
        let event_count_before = event::counter(&gateway_before.protocol_token_address_updated_events);

        // Call the function that might modify state
        setting_manager_bool(account, string::utf8(b"token"), test_token_address, 1);

        // Get state AFTER the function call
        let gateway_after = borrow_global<GatewaySettings>(expected_resource_account_address);
        let supported_tokens_after = vector::length(&gateway_after.supported_tokens);
        let event_count_after = event::counter(&gateway_after.protocol_token_address_updated_events);

        // Compare before and after states
        assert!((supported_tokens_before + 1) == supported_tokens_after, 0);
        assert!((event_count_before + 1) == event_count_after, 0);
    }

    #[test(account = @gateway, test_user = @0x2)]
    public fun test_setting_manager_bool_success_status_2(
        account: &signer,
        test_user: &signer
    ) acquires GatewaySettings {
        let account_address = signer::address_of(account);
        let test_address = signer::address_of(test_user);
        account::create_account_for_test(account_address);
        account::create_account_for_test(test_address);

        // Set up timestamp for testing
        let aptos_framework = account::create_account_for_test(@aptos_framework);
        timestamp::set_time_has_started_for_testing(&aptos_framework);

        // Initialize the module
        init_module(account);

        let expected_resource_account_address = account::create_resource_address(&account_address, SEED);
        let test_token_address = @0x3;
        let test_token_address_2 = @0x4;

        // Get state BEFORE the function call
        let gateway_before = borrow_global<GatewaySettings>(expected_resource_account_address);
        let event_count_before = event::counter(&gateway_before.protocol_token_address_updated_events);

        // Call the function that might modify state
        setting_manager_bool(account, string::utf8(b"token"), test_token_address, 1);
        setting_manager_bool(account, string::utf8(b"token"), test_token_address_2, 1);
        setting_manager_bool(account, string::utf8(b"token"), test_token_address, 2);

        // Get state AFTER the function call
        let gateway_after = borrow_global<GatewaySettings>(expected_resource_account_address);
        let supported_tokens_after = vector::length(&gateway_after.supported_tokens);
        let event_count_after = event::counter(&gateway_after.protocol_token_address_updated_events);

        assert!(supported_tokens_after == 1, 0);
        assert!((event_count_before + 3) == event_count_after, 0);
    }

    #[test(account = @gateway, test_user = @0x2)]
    #[expected_failure(abort_code = E_TOKEN_NOT_FOUND)]
    public fun test_setting_manager_bool_error_status_2(
        account: &signer,
        test_user: &signer
    ) acquires GatewaySettings {
        let account_address = signer::address_of(account);
        let test_address = signer::address_of(test_user);
        account::create_account_for_test(account_address);
        account::create_account_for_test(test_address);

        // Set up timestamp for testing
        let aptos_framework = account::create_account_for_test(@aptos_framework);
        timestamp::set_time_has_started_for_testing(&aptos_framework);

        // Initialize the module
        init_module(account);

        let expected_resource_account_address = account::create_resource_address(&account_address, SEED);
        let test_token_address = @0x3;

        // Get state BEFORE the function call
        let gateway_before = borrow_global<GatewaySettings>(expected_resource_account_address);
        let supported_tokens_before = vector::length(&gateway_before.supported_tokens);
        let event_count_before = event::counter(&gateway_before.protocol_token_address_updated_events);

        // Call the function that might modify state
        setting_manager_bool(account, string::utf8(b"token"), test_token_address, 2);

        // Get state AFTER the function call
        let gateway_after = borrow_global<GatewaySettings>(expected_resource_account_address);
        let supported_tokens_after = vector::length(&gateway_after.supported_tokens);
        let event_count_after = event::counter(&gateway_after.protocol_token_address_updated_events);

        // Compare before and after states
        assert!(supported_tokens_before == supported_tokens_after, 0);
        assert!(event_count_before == event_count_after, 0);
    }

    #[test(account = @gateway, test_user = @0x2)]
    #[expected_failure(abort_code = E_NOT_OWNER)]
    public fun test_update_protocol_fee_error_not_owner(
        account: &signer,
        test_user: &signer
    ) acquires GatewaySettings {
        let account_address = signer::address_of(account);
        let test_address = signer::address_of(test_user);
        account::create_account_for_test(account_address);
        account::create_account_for_test(test_address);

        // Set up timestamp for testing
        let aptos_framework = account::create_account_for_test(@aptos_framework);
        timestamp::set_time_has_started_for_testing(&aptos_framework);

        // Initialize the module
        init_module(account);

        let expected_resource_account_address = account::create_resource_address(&account_address, SEED);

        let gateway_before = borrow_global<GatewaySettings>(expected_resource_account_address);
        let protocol_fee_before = gateway_before.protocol_fee_percent;

        update_protocol_fee(test_user, 3);

        let gateway_after = borrow_global<GatewaySettings>(expected_resource_account_address);
        let protocol_fee_after =  gateway_after.protocol_fee_percent;

        assert!(protocol_fee_before == protocol_fee_after, 0);
        assert!(event::counter(&gateway_after.protocol_fee_updated_events) == 0, 0);
    }


    #[test(account = @gateway, test_user = @0x2)]
    public fun test_update_protocol_fee_succcess(
        account: &signer,
        test_user: &signer
    ) acquires GatewaySettings {
        let account_address = signer::address_of(account);
        let test_address = signer::address_of(test_user);
        account::create_account_for_test(account_address);
        account::create_account_for_test(test_address);

        // Set up timestamp for testing
        let aptos_framework = account::create_account_for_test(@aptos_framework);
        timestamp::set_time_has_started_for_testing(&aptos_framework);

        // Initialize the module
        init_module(account);

        let expected_resource_account_address = account::create_resource_address(&account_address, SEED);

        let gateway_before = borrow_global<GatewaySettings>(expected_resource_account_address);
        let protocol_fee_before = gateway_before.protocol_fee_percent;

        let new_protocol_fee = 3;

        assert!(protocol_fee_before != new_protocol_fee, 0);
        update_protocol_fee(account, new_protocol_fee);

        let gateway_after = borrow_global<GatewaySettings>(expected_resource_account_address);
        let protocol_fee_after =  gateway_after.protocol_fee_percent;

        assert!(protocol_fee_before != protocol_fee_after, 0);
        assert!(event::counter(&gateway_after.protocol_fee_updated_events) == 1, 0);
    }

    #[test(account = @gateway, test_user = @0x2)]
    #[expected_failure(abort_code = E_NOT_OWNER)]
    public fun test_update_protocol_address_not_owner(
        account: &signer,
        test_user: &signer
    ) acquires GatewaySettings {
        let account_address = signer::address_of(account);
        let test_address = signer::address_of(test_user);
        account::create_account_for_test(account_address);
        account::create_account_for_test(test_address);

        // Set up timestamp for testing
        let aptos_framework = account::create_account_for_test(@aptos_framework);
        timestamp::set_time_has_started_for_testing(&aptos_framework);

        // Initialize the module
        init_module(account);

        let expected_resource_account_address = account::create_resource_address(&account_address, SEED);

        let gateway_before = borrow_global<GatewaySettings>(expected_resource_account_address);
        let protocol_treasury_address_before = gateway_before.treasury_address;

        let address = @0x03;
        let what = string::utf8(b"treasury");

        update_protocol_address(test_user, what, address);

        let gateway_after = borrow_global<GatewaySettings>(expected_resource_account_address);
        let protocol_treasury_address_after =  gateway_after.treasury_address;

        assert!(protocol_treasury_address_before == protocol_treasury_address_after, 0);
        assert!(event::counter(&gateway_after.protocol_address_updated_events) == 0, 0);
    }

    #[test(account = @gateway, test_user = @0x2)]
    #[expected_failure(abort_code = E_ZERO_ADDRESS)]
    public fun test_update_protocol_address_not_zero_address(
        account: &signer,
        test_user: &signer
    ) acquires GatewaySettings {
        let account_address = signer::address_of(account);
        let test_address = signer::address_of(test_user);
        account::create_account_for_test(account_address);
        account::create_account_for_test(test_address);

        // Set up timestamp for testing
        let aptos_framework = account::create_account_for_test(@aptos_framework);
        timestamp::set_time_has_started_for_testing(&aptos_framework);

        // Initialize the module
        init_module(account);

        let expected_resource_account_address = account::create_resource_address(&account_address, SEED);

        let gateway_before = borrow_global<GatewaySettings>(expected_resource_account_address);
        let protocol_treasury_address_before = gateway_before.treasury_address;

        let address = @0x0;
        let what = string::utf8(b"treasury");

        update_protocol_address(account, what, address);

        let gateway_after = borrow_global<GatewaySettings>(expected_resource_account_address);
        let protocol_treasury_address_after =  gateway_after.treasury_address;

        assert!(protocol_treasury_address_before == protocol_treasury_address_after, 0);
        assert!(event::counter(&gateway_after.protocol_address_updated_events) == 0, 0);
    }

    #[test(account = @gateway, test_user = @0x2)]
    public fun test_update_protocol_address_not_invalid_what(
        account: &signer,
        test_user: &signer
    ) acquires GatewaySettings {
        let account_address = signer::address_of(account);
        let test_address = signer::address_of(test_user);
        account::create_account_for_test(account_address);
        account::create_account_for_test(test_address);

        // Set up timestamp for testing
        let aptos_framework = account::create_account_for_test(@aptos_framework);
        timestamp::set_time_has_started_for_testing(&aptos_framework);

        // Initialize the module
        init_module(account);

        let expected_resource_account_address = account::create_resource_address(&account_address, SEED);

        let gateway_before = borrow_global<GatewaySettings>(expected_resource_account_address);
        let protocol_treasury_address_before = gateway_before.treasury_address;
        let protocol_aggregator_address_before = gateway_before.aggregator_address;

        let address = @0x3;
        let what = string::utf8(b"treasur");
        let what_agg = string::utf8(b"aggregato");

        update_protocol_address(account, what, address);
        update_protocol_address(account, what_agg, address);

        let gateway_after = borrow_global<GatewaySettings>(expected_resource_account_address);
        let protocol_treasury_address_after =  gateway_after.treasury_address;
        let protocol_aggregator_address_after = gateway_after.aggregator_address;

        assert!(protocol_treasury_address_before == protocol_treasury_address_after, 0);
        assert!(protocol_aggregator_address_after == protocol_aggregator_address_after, 0);
        assert!(event::counter(&gateway_after.protocol_address_updated_events) == 0, 0);
    }

    #[test(account = @gateway, test_user = @0x2)]
    public fun test_update_protocol_address_not_invalid_what_treasury_only(
        account: &signer,
        test_user: &signer
    ) acquires GatewaySettings {
        let account_address = signer::address_of(account);
        let test_address = signer::address_of(test_user);
        account::create_account_for_test(account_address);
        account::create_account_for_test(test_address);

        // Set up timestamp for testing
        let aptos_framework = account::create_account_for_test(@aptos_framework);
        timestamp::set_time_has_started_for_testing(&aptos_framework);

        // Initialize the module
        init_module(account);

        let expected_resource_account_address = account::create_resource_address(&account_address, SEED);

        let gateway_before = borrow_global<GatewaySettings>(expected_resource_account_address);
        let protocol_treasury_address_before = gateway_before.treasury_address;
        let protocol_aggregator_address_before = gateway_before.aggregator_address;

        let address = @0x3;
        let what = string::utf8(b"treasur");
        let what_agg = string::utf8(b"aggregator");

        update_protocol_address(account, what, address);
        update_protocol_address(account, what_agg, address);

        let gateway_after = borrow_global<GatewaySettings>(expected_resource_account_address);
        let protocol_treasury_address_after =  gateway_after.treasury_address;
        let protocol_aggregator_address_after = gateway_after.aggregator_address;

        assert!(protocol_treasury_address_before == protocol_treasury_address_after, 0);
        assert!(protocol_aggregator_address_before != protocol_aggregator_address_after, 0);
        assert!(event::counter(&gateway_after.protocol_address_updated_events) == 1, 0);
    }

    #[test(account = @gateway, test_user = @0x2)]
    public fun test_update_protocol_address_not_invalid_what_aggregator_only(
        account: &signer,
        test_user: &signer
    ) acquires GatewaySettings {
        let account_address = signer::address_of(account);
        let test_address = signer::address_of(test_user);
        account::create_account_for_test(account_address);
        account::create_account_for_test(test_address);

        // Set up timestamp for testing
        let aptos_framework = account::create_account_for_test(@aptos_framework);
        timestamp::set_time_has_started_for_testing(&aptos_framework);

        // Initialize the module
        init_module(account);

        let expected_resource_account_address = account::create_resource_address(&account_address, SEED);

        let gateway_before = borrow_global<GatewaySettings>(expected_resource_account_address);
        let protocol_treasury_address_before = gateway_before.treasury_address;
        let protocol_aggregator_address_before = gateway_before.aggregator_address;

        let address = @0x3;
        let what = string::utf8(b"treasury");
        let what_agg = string::utf8(b"aggregato");

        update_protocol_address(account, what, address);
        update_protocol_address(account, what_agg, address);

        let gateway_after = borrow_global<GatewaySettings>(expected_resource_account_address);
        let protocol_treasury_address_after =  gateway_after.treasury_address;
        let protocol_aggregator_address_after = gateway_after.aggregator_address;

        assert!(protocol_treasury_address_before != protocol_treasury_address_after, 0);
        assert!(protocol_aggregator_address_before == protocol_aggregator_address_after, 0);
        assert!(event::counter(&gateway_after.protocol_address_updated_events) == 1, 0);
    }

    #[test(account = @gateway, test_user = @0x2)]
    public fun test_update_protocol_address_success_only_treasury(
        account: &signer,
        test_user: &signer
    ) acquires GatewaySettings {
        let account_address = signer::address_of(account);
        let test_address = signer::address_of(test_user);
        account::create_account_for_test(account_address);
        account::create_account_for_test(test_address);

        // Set up timestamp for testing
        let aptos_framework = account::create_account_for_test(@aptos_framework);
        timestamp::set_time_has_started_for_testing(&aptos_framework);

        // Initialize the module
        init_module(account);

        let expected_resource_account_address = account::create_resource_address(&account_address, SEED);

        let gateway_before = borrow_global<GatewaySettings>(expected_resource_account_address);
        let protocol_treasury_address_before = gateway_before.treasury_address;

        let address = @0x3;
        let what = string::utf8(b"treasury");

        update_protocol_address(account, what, address);

        let gateway_after = borrow_global<GatewaySettings>(expected_resource_account_address);
        let protocol_treasury_address_after =  gateway_after.treasury_address;

        assert!(protocol_treasury_address_before != protocol_treasury_address_after, 0);
        assert!(event::counter(&gateway_after.protocol_address_updated_events) == 1, 0);
    }


    #[test(account = @gateway, test_user = @0x2)]
    public fun test_update_protocol_address_success_only_aggregator(
        account: &signer,
        test_user: &signer
    ) acquires GatewaySettings {
        let account_address = signer::address_of(account);
        let test_address = signer::address_of(test_user);
        account::create_account_for_test(account_address);
        account::create_account_for_test(test_address);

        // Set up timestamp for testing
        let aptos_framework = account::create_account_for_test(@aptos_framework);
        timestamp::set_time_has_started_for_testing(&aptos_framework);

        // Initialize the module
        init_module(account);

        let expected_resource_account_address = account::create_resource_address(&account_address, SEED);

        let gateway_before = borrow_global<GatewaySettings>(expected_resource_account_address);
        let protocol_aggregator_address_before = gateway_before.aggregator_address;

        let address = @0x3;
        let what = string::utf8(b"aggregator");

        update_protocol_address(account, what, address);

        let gateway_after = borrow_global<GatewaySettings>(expected_resource_account_address);
        let protocol_aggregator_address_after=  gateway_after.aggregator_address;

        assert!(protocol_aggregator_address_before != protocol_aggregator_address_after, 0);
        assert!(event::counter(&gateway_after.protocol_address_updated_events) == 1, 0);
    }

    #[test(account = @gateway, test_user = @0x2)]
    public fun test_update_protocol_address_both_aggregator_and_treasury(
        account: &signer,
        test_user: &signer
    ) acquires GatewaySettings {
        let account_address = signer::address_of(account);
        let test_address = signer::address_of(test_user);
        account::create_account_for_test(account_address);
        account::create_account_for_test(test_address);

        // Set up timestamp for testing
        let aptos_framework = account::create_account_for_test(@aptos_framework);
        timestamp::set_time_has_started_for_testing(&aptos_framework);

        // Initialize the module
        init_module(account);

        let expected_resource_account_address = account::create_resource_address(&account_address, SEED);

        let gateway_before = borrow_global<GatewaySettings>(expected_resource_account_address);
        let protocol_treasury_address_before = gateway_before.treasury_address;
        let protocol_aggregator_address_before = gateway_before.aggregator_address;

        let address = @0x3;
        let what = string::utf8(b"treasury");
        let what_agg = string::utf8(b"aggregator");

        update_protocol_address(account, what, address);
        update_protocol_address(account, what_agg, address);

        let gateway_after = borrow_global<GatewaySettings>(expected_resource_account_address);
        let protocol_treasury_address_after =  gateway_after.treasury_address;
        let protocol_aggregator_address_after = gateway_after.aggregator_address;

        assert!(protocol_treasury_address_before != protocol_treasury_address_after, 0);
        assert!(protocol_aggregator_address_before != protocol_aggregator_address_after, 0);
        assert!(event::counter(&gateway_after.protocol_address_updated_events) == 2, 0);
    }

    #[test(account = @gateway, test_user = @0x2)]
    #[expected_failure(abort_code = E_NOT_OWNER)]
    public fun test_pause_error_not_owner(
        account: &signer,
        test_user: &signer
    ) acquires GatewaySettings {
        let account_address = signer::address_of(account);
        let test_address = signer::address_of(test_user);
        account::create_account_for_test(account_address);
        account::create_account_for_test(test_address);

        // Set up timestamp for testing
        let aptos_framework = account::create_account_for_test(@aptos_framework);
        timestamp::set_time_has_started_for_testing(&aptos_framework);

        // Initialize the module
        init_module(account);

        let expected_resource_account_address = account::create_resource_address(&account_address, SEED);

        pause(test_user);

        let gateway = borrow_global<GatewaySettings>(expected_resource_account_address);
        assert!(gateway.paused == false, 0);
    }

    #[test(account = @gateway, test_user = @0x2)]
    #[expected_failure(abort_code = E_PAUSED)]
    public fun test_pause_error_already_paused(
        account: &signer,
        test_user: &signer
    ) acquires GatewaySettings {
        let account_address = signer::address_of(account);
        let test_address = signer::address_of(test_user);
        account::create_account_for_test(account_address);
        account::create_account_for_test(test_address);

        // Set up timestamp for testing
        let aptos_framework = account::create_account_for_test(@aptos_framework);
        timestamp::set_time_has_started_for_testing(&aptos_framework);

        // Initialize the module
        init_module(account);

        let expected_resource_account_address = account::create_resource_address(&account_address, SEED);

        pause(account);
        pause(account);

        let gateway = borrow_global<GatewaySettings>(expected_resource_account_address);
        assert!(gateway.paused == true, 0);
    }

    #[test(account = @gateway, test_user = @0x2)]
    public fun test_pause_success(
        account: &signer,
        test_user: &signer
    ) acquires GatewaySettings {
        let account_address = signer::address_of(account);
        let test_address = signer::address_of(test_user);
        account::create_account_for_test(account_address);
        account::create_account_for_test(test_address);

        // Set up timestamp for testing
        let aptos_framework = account::create_account_for_test(@aptos_framework);
        timestamp::set_time_has_started_for_testing(&aptos_framework);

        // Initialize the module
        init_module(account);

        let expected_resource_account_address = account::create_resource_address(&account_address, SEED);

        pause(account);

        let gateway = borrow_global<GatewaySettings>(expected_resource_account_address);
        assert!(gateway.paused == true, 0);
    }

    #[test(account = @gateway, test_user = @0x2)]
    #[expected_failure(abort_code = E_NOT_OWNER)]
    public fun test_unpause_error_not_owner(
        account: &signer,
        test_user: &signer
    ) acquires GatewaySettings {
        let account_address = signer::address_of(account);
        let test_address = signer::address_of(test_user);
        account::create_account_for_test(account_address);
        account::create_account_for_test(test_address);

        // Set up timestamp for testing
        let aptos_framework = account::create_account_for_test(@aptos_framework);
        timestamp::set_time_has_started_for_testing(&aptos_framework);

        // Initialize the module
        init_module(account);

        let expected_resource_account_address = account::create_resource_address(&account_address, SEED);

        unpause(test_user);

        let gateway = borrow_global<GatewaySettings>(expected_resource_account_address);
        assert!(gateway.paused == false, 0);
    }

    #[test(account = @gateway, test_user = @0x2)]
    #[expected_failure(abort_code = E_NOT_PAUSED)]
    public fun test_unpause_error_already_unpaused(
        account: &signer,
        test_user: &signer
    ) acquires GatewaySettings {
        let account_address = signer::address_of(account);
        let test_address = signer::address_of(test_user);
        account::create_account_for_test(account_address);
        account::create_account_for_test(test_address);

        // Set up timestamp for testing
        let aptos_framework = account::create_account_for_test(@aptos_framework);
        timestamp::set_time_has_started_for_testing(&aptos_framework);

        // Initialize the module
        init_module(account);

        let expected_resource_account_address = account::create_resource_address(&account_address, SEED);

        unpause(account);

        let gateway = borrow_global<GatewaySettings>(expected_resource_account_address);
        assert!(gateway.paused == false, 0);
    }

    #[test(account = @gateway, test_user = @0x2)]
    public fun test_unpause_success(
        account: &signer,
        test_user: &signer
    ) acquires GatewaySettings {
        let account_address = signer::address_of(account);
        let test_address = signer::address_of(test_user);
        account::create_account_for_test(account_address);
        account::create_account_for_test(test_address);

        // Set up timestamp for testing
        let aptos_framework = account::create_account_for_test(@aptos_framework);
        timestamp::set_time_has_started_for_testing(&aptos_framework);

        // Initialize the module
        init_module(account);

        let expected_resource_account_address = account::create_resource_address(&account_address, SEED);

        pause(account);
        unpause(account);

        let gateway = borrow_global<GatewaySettings>(expected_resource_account_address);
        assert!(gateway.paused == false, 0);
    }

    #[test(account = @gateway, test_user = @0x2)]
    #[expected_failure(abort_code = E_PAUSED)]
    public fun test_create_order_error_paused(
        account: &signer,
        test_user: &signer
    ) acquires GatewaySettings {
        let account_address = signer::address_of(account);
        let test_address = signer::address_of(test_user);
        account::create_account_for_test(account_address);
        account::create_account_for_test(test_address);

        // Set up timestamp for testing
        let aptos_framework = account::create_account_for_test(@aptos_framework);
        timestamp::set_time_has_started_for_testing(&aptos_framework);

        // Initialize the module
        init_module(account);

        let expected_resource_account_address = account::create_resource_address(&account_address, SEED);

        pause(account);

        // Create USDC metadata object
        let usdc_metadata_ref = object::create_named_object(test_user, b"USDC");
        primary_fungible_store::create_primary_store_enabled_fungible_asset(
            &usdc_metadata_ref,
            option::none(), // No maximum supply
            string::utf8(b"USD Coin"), // name
            string::utf8(b"USDC"), // symbol
            6, // decimals for USDC
            string::utf8(b"[invalid url, do not cite]"), // icon_uri
            string::utf8(b"[invalid url, do not cite]") // project_uri
        );
        let usdc_address = object::address_from_constructor_ref(&usdc_metadata_ref);

        let token_metadata = object::address_to_object<fungible_asset::Metadata>(usdc_address);

        let before_call_amount_for_caller = primary_fungible_store::balance(test_address, token_metadata);
        let before_call_amount_for_resource_addr = primary_fungible_store::balance(expected_resource_account_address, token_metadata);

        let amount = 1000;
        let rate = 1560;
        let sender_fee_address = @0x03;
        let sender_fee = 3;
        let message_hash = string::utf8(b"order created");

        create_order(test_user, usdc_address, amount, rate, sender_fee_address, sender_fee, test_address, message_hash);

        let after_call_amount_for_caller = primary_fungible_store::balance(test_address, token_metadata);
        let after_call_amount_for_resource_addr = primary_fungible_store::balance(expected_resource_account_address, token_metadata);

        print(&amount);

        let gateway = borrow_global<GatewaySettings>(expected_resource_account_address);
        assert!(gateway.paused == true, 0);

        assert!(before_call_amount_for_caller == after_call_amount_for_caller, 1);
        assert!(before_call_amount_for_resource_addr == after_call_amount_for_resource_addr, 1);
        assert!(vector::length(&gateway.order_store) == 0, 1);
        assert!(event::counter(&gateway.order_created_events) == 0, 1);
    }


    #[test(account = @gateway, test_user = @0x2)]
    #[expected_failure(abort_code = E_TOKEN_NOT_SUPPORTED)]
    public fun test_create_order_token_not_supported(
        account: &signer,
        test_user: &signer
    ) acquires GatewaySettings {
        let account_address = signer::address_of(account);
        let test_address = signer::address_of(test_user);
        account::create_account_for_test(account_address);
        account::create_account_for_test(test_address);

        // Set up timestamp for testing
        let aptos_framework = account::create_account_for_test(@aptos_framework);
        timestamp::set_time_has_started_for_testing(&aptos_framework);

        // Initialize the module
        init_module(account);

        let expected_resource_account_address = account::create_resource_address(&account_address, SEED);

        let usdc_address = @0xbae207659db88bea0cbead6da0ed00aac12edcdda169e591cd41c94180b46f3b;
        let amount = 1000;
        let rate = 1560;
        let message_hash = string::utf8(b"order created");
        let sender_fee_address = @0x03;
        let sender_fee = 3;
        // setting_manager_bool(account, string::utf8(b"token"), usdc_address, 1);

        create_order(test_user, usdc_address, amount, rate, sender_fee_address, sender_fee, test_address, message_hash);

        let gateway = borrow_global<GatewaySettings>(expected_resource_account_address);
        assert!(vector::length(&gateway.supported_tokens) == 0, 1);
        assert!(vector::length(&gateway.order_store) == 0, 1);
        assert!(event::counter(&gateway.order_created_events) == 0, 1);
    }


    // assert_amount_not_zero(amount);
    // assert_not_zero_address(refund_address);
    // if (sender_fee != 0) assert_not_zero_address(sender_fee_recipient);
    // assert_valid_message_hash(&message_hash);

    #[test(account = @gateway, test_user = @0x2)]
    #[expected_failure(abort_code = E_AMOUNT_ZERO)]
    public fun test_create_order_zero_amount(
        account: &signer,
        test_user: &signer
    ) acquires GatewaySettings {
        let account_address = signer::address_of(account);
        let test_address = signer::address_of(test_user);
        account::create_account_for_test(account_address);
        account::create_account_for_test(test_address);

        // Set up timestamp for testing
        let aptos_framework = account::create_account_for_test(@aptos_framework);
        timestamp::set_time_has_started_for_testing(&aptos_framework);

        // Initialize the module
        init_module(account);

        let expected_resource_account_address = account::create_resource_address(&account_address, SEED);

        let usdc_address = @0xbae207659db88bea0cbead6da0ed00aac12edcdda169e591cd41c94180b46f3b;
        let amount = 0;
        let rate = 1560;
        let message_hash = string::utf8(b"order created");
        let sender_fee_address = @0x03;
        let sender_fee = 3;

        setting_manager_bool(account, string::utf8(b"token"), usdc_address, 1);

        create_order(test_user, usdc_address, amount, rate, sender_fee_address, sender_fee, test_address, message_hash);

        let gateway = borrow_global<GatewaySettings>(expected_resource_account_address);
        assert!(vector::length(&gateway.supported_tokens) == 1, 1);
        assert!(vector::length(&gateway.order_store) == 0, 1);
        assert!(event::counter(&gateway.order_created_events) == 0, 1);
    }

    #[test(account = @gateway, test_user = @0x2)]
    #[expected_failure(abort_code = E_ZERO_ADDRESS)]
    public fun test_create_order_zero_refund_address(
        account: &signer,
        test_user: &signer
    ) acquires GatewaySettings {
        let account_address = signer::address_of(account);
        let test_address = signer::address_of(test_user);
        account::create_account_for_test(account_address);
        account::create_account_for_test(test_address);

        // Set up timestamp for testing
        let aptos_framework = account::create_account_for_test(@aptos_framework);
        timestamp::set_time_has_started_for_testing(&aptos_framework);

        // Initialize the module
        init_module(account);

        let expected_resource_account_address = account::create_resource_address(&account_address, SEED);

        let usdc_address = @0xbae207659db88bea0cbead6da0ed00aac12edcdda169e591cd41c94180b46f3b;
        let amount = 1000;
        let rate = 1560;
        let message_hash = string::utf8(b"order created");
        let sender_fee_address = @0x03;
        let sender_fee = 3;

        setting_manager_bool(account, string::utf8(b"token"), usdc_address, 1);

        create_order(test_user, usdc_address, amount, rate, sender_fee_address, sender_fee, @0x0, message_hash);

        let gateway = borrow_global<GatewaySettings>(expected_resource_account_address);
        assert!(vector::length(&gateway.supported_tokens) == 1, 1);
        assert!(vector::length(&gateway.order_store) == 0, 1);
        assert!(event::counter(&gateway.order_created_events) == 0, 1);
    }


    #[test(account = @gateway, test_user = @0x2)]
    #[expected_failure(abort_code = E_ZERO_ADDRESS)]
    public fun test_create_order_zero_sender_fee_recipient_address(
        account: &signer,
        test_user: &signer
    ) acquires GatewaySettings {
        let account_address = signer::address_of(account);
        let test_address = signer::address_of(test_user);
        account::create_account_for_test(account_address);
        account::create_account_for_test(test_address);

        // Set up timestamp for testing
        let aptos_framework = account::create_account_for_test(@aptos_framework);
        timestamp::set_time_has_started_for_testing(&aptos_framework);

        // Initialize the module
        init_module(account);

        let expected_resource_account_address = account::create_resource_address(&account_address, SEED);

        let usdc_address = @0xbae207659db88bea0cbead6da0ed00aac12edcdda169e591cd41c94180b46f3b;
        let amount = 1000;
        let rate = 1560;
        let message_hash = string::utf8(b"order created");
        let sender_fee_address = @0x0;
        let sender_fee = 3;

        setting_manager_bool(account, string::utf8(b"token"), usdc_address, 1);

        create_order(test_user, usdc_address, amount, rate, sender_fee_address, sender_fee, test_address, message_hash);

        let gateway = borrow_global<GatewaySettings>(expected_resource_account_address);
        assert!(vector::length(&gateway.supported_tokens) == 1, 1);
        assert!(vector::length(&gateway.order_store) == 0, 1);
        assert!(event::counter(&gateway.order_created_events) == 0, 1);
    }

    #[test(account = @gateway, test_user = @0x2)]
    #[expected_failure(abort_code = E_INVALID_MESSAGE_HASH)]
    public fun test_create_order_invalid_message_hash(
        account: &signer,
        test_user: &signer
    ) acquires GatewaySettings {
        let account_address = signer::address_of(account);
        let test_address = signer::address_of(test_user);
        account::create_account_for_test(account_address);
        account::create_account_for_test(test_address);

        // Set up timestamp for testing
        let aptos_framework = account::create_account_for_test(@aptos_framework);
        timestamp::set_time_has_started_for_testing(&aptos_framework);

        // Initialize the module
        init_module(account);

        let expected_resource_account_address = account::create_resource_address(&account_address, SEED);

        let usdc_address = @0xbae207659db88bea0cbead6da0ed00aac12edcdda169e591cd41c94180b46f3b;
        let amount = 1000;
        let rate = 1560;
        let message_hash = string::utf8(b"");
        let sender_fee_address = @0x03;
        let sender_fee = 3;
        let aggregator_addr = @0x04;
        let treasury_addr = @0x05;

        setting_manager_bool(account, string::utf8(b"token"), usdc_address, 1);
        update_protocol_address(account, string::utf8(b"treasury"), treasury_addr);
        update_protocol_address(account, string::utf8(b"aggregator"), aggregator_addr);

        create_order(test_user, usdc_address, amount, rate, sender_fee_address, sender_fee, test_address, message_hash);

        let gateway = borrow_global<GatewaySettings>(expected_resource_account_address);
        assert!(vector::length(&gateway.supported_tokens) == 1, 1);
        assert!(vector::length(&gateway.order_store) == 0, 1);
        assert!(event::counter(&gateway.order_created_events) == 0, 1);
    }

    #[test(account = @gateway, test_user = @0x2)]
    #[expected_failure(abort_code = E_ZERO_ADDRESS)]
    public fun test_create_order_invalid_aggregator_address(
        account: &signer,
        test_user: &signer
    ) acquires GatewaySettings {
        let account_address = signer::address_of(account);
        let test_address = signer::address_of(test_user);
        account::create_account_for_test(account_address);
        account::create_account_for_test(test_address);

        // Set up timestamp for testing
        let aptos_framework = account::create_account_for_test(@aptos_framework);
        timestamp::set_time_has_started_for_testing(&aptos_framework);

        // Initialize the module
        init_module(account);

        let expected_resource_account_address = account::create_resource_address(&account_address, SEED);

        let usdc_address = @0xbae207659db88bea0cbead6da0ed00aac12edcdda169e591cd41c94180b46f3b;
        let amount = 1000;
        let rate = 1560;
        let message_hash = string::utf8(b"order created");
        let sender_fee_address = @0x03;
        let sender_fee = 3;
        let aggregator_addr = @0x0;
        let treasury_addr = @0x05;

        setting_manager_bool(account, string::utf8(b"token"), usdc_address, 1);
        update_protocol_address(account, string::utf8(b"treasury"), treasury_addr);
        update_protocol_address(account, string::utf8(b"aggregator"), aggregator_addr);

        create_order(test_user, usdc_address, amount, rate, sender_fee_address, sender_fee, test_address, message_hash);

        let gateway = borrow_global<GatewaySettings>(expected_resource_account_address);
        assert!(vector::length(&gateway.supported_tokens) == 1, 1);
        assert!(vector::length(&gateway.order_store) == 0, 1);
        assert!(event::counter(&gateway.order_created_events) == 0, 1);
    }

    #[test(account = @gateway, test_user = @0x2)]
    #[expected_failure(abort_code = E_ZERO_ADDRESS)]
    public fun test_create_order_invalid_treasury_address(
        account: &signer,
        test_user: &signer
    ) acquires GatewaySettings {
        let account_address = signer::address_of(account);
        let test_address = signer::address_of(test_user);
        account::create_account_for_test(account_address);
        account::create_account_for_test(test_address);

        // Set up timestamp for testing
        let aptos_framework = account::create_account_for_test(@aptos_framework);
        timestamp::set_time_has_started_for_testing(&aptos_framework);

        // Initialize the module
        init_module(account);

        let expected_resource_account_address = account::create_resource_address(&account_address, SEED);

        let usdc_address = @0xbae207659db88bea0cbead6da0ed00aac12edcdda169e591cd41c94180b46f3b;
        let amount = 1000;
        let rate = 1560;
        let message_hash = string::utf8(b"");
        let sender_fee_address = @0x03;
        let sender_fee = 3;
        let aggregator_addr = @0x04;
        let treasury_addr = @0x0;

        setting_manager_bool(account, string::utf8(b"token"), usdc_address, 1);
        update_protocol_address(account, string::utf8(b"treasury"), treasury_addr);
        update_protocol_address(account, string::utf8(b"aggregator"), aggregator_addr);

        create_order(test_user, usdc_address, amount, rate, sender_fee_address, sender_fee, test_address, message_hash);

        let gateway = borrow_global<GatewaySettings>(expected_resource_account_address);
        assert!(vector::length(&gateway.supported_tokens) == 1, 1);
        assert!(vector::length(&gateway.order_store) == 0, 1);
        assert!(event::counter(&gateway.order_created_events) == 0, 1);
    }


    #[test(account = @gateway, test_user = @0x2)]
    #[expected_failure(abort_code = E_AMOUNT_ZERO)]
    public fun test_create_order_invalid_amount(
        account: &signer,
        test_user: &signer
    ) acquires GatewaySettings {
        let account_address = signer::address_of(account);
        let test_address = signer::address_of(test_user);
        account::create_account_for_test(account_address);
        account::create_account_for_test(test_address);

        // Set up timestamp for testing
        let aptos_framework = account::create_account_for_test(@aptos_framework);
        timestamp::set_time_has_started_for_testing(&aptos_framework);

        // Initialize the module
        init_module(account);

        let expected_resource_account_address = account::create_resource_address(&account_address, SEED);

        let usdc_address = @0xbae207659db88bea0cbead6da0ed00aac12edcdda169e591cd41c94180b46f3b;
        let amount = 0;
        let rate = 1560;
        let message_hash = string::utf8(b"order created");
        let sender_fee_address = @0x03;
        let sender_fee = 3;
        let aggregator_addr = @0x04;
        let treasury_addr = @0x05;

        setting_manager_bool(account, string::utf8(b"token"), usdc_address, 1);
        update_protocol_address(account, string::utf8(b"treasury"), treasury_addr);
        update_protocol_address(account, string::utf8(b"aggregator"), aggregator_addr);

        create_order(test_user, usdc_address, amount, rate, sender_fee_address, sender_fee, test_address, message_hash);

        let gateway = borrow_global<GatewaySettings>(expected_resource_account_address);
        assert!(vector::length(&gateway.supported_tokens) == 1, 1);
        assert!(vector::length(&gateway.order_store) == 0, 1);
        assert!(event::counter(&gateway.order_created_events) == 0, 1);
    }

    #[test(account = @gateway, test_user = @0x2)]
    #[expected_failure(abort_code = E_ZERO_ADDRESS)]
    public fun test_create_order_invalid_refund_address(
        account: &signer,
        test_user: &signer
    ) acquires GatewaySettings {
        let account_address = signer::address_of(account);
        let test_address = signer::address_of(test_user);
        account::create_account_for_test(account_address);
        account::create_account_for_test(test_address);

        // Set up timestamp for testing
        let aptos_framework = account::create_account_for_test(@aptos_framework);
        timestamp::set_time_has_started_for_testing(&aptos_framework);

        // Initialize the module
        init_module(account);

        let expected_resource_account_address = account::create_resource_address(&account_address, SEED);

        let usdc_address = @0xbae207659db88bea0cbead6da0ed00aac12edcdda169e591cd41c94180b46f3b;
        let amount = 1000;
        let rate = 1560;
        let message_hash = string::utf8(b"order created");
        let sender_fee_address = @0x03;
        let sender_fee = 3;
        let aggregator_addr = @0x04;
        let treasury_addr = @0x0;

        setting_manager_bool(account, string::utf8(b"token"), usdc_address, 1);
        update_protocol_address(account, string::utf8(b"treasury"), treasury_addr);
        update_protocol_address(account, string::utf8(b"aggregator"), aggregator_addr);

        create_order(test_user, usdc_address, amount, rate, sender_fee_address, sender_fee, @0x0, message_hash);

        let gateway = borrow_global<GatewaySettings>(expected_resource_account_address);
        assert!(vector::length(&gateway.supported_tokens) == 1, 1);
        assert!(vector::length(&gateway.order_store) == 0, 1);
        assert!(event::counter(&gateway.order_created_events) == 0, 1);
    }

    #[test(account = @gateway, test_user = @0x2)]
    #[expected_failure(abort_code = E_PAUSED)]
    public fun test_create_order_paused(
        account: &signer,
        test_user: &signer
    ) acquires GatewaySettings {
        let account_address = signer::address_of(account);
        let test_address = signer::address_of(test_user);
        account::create_account_for_test(account_address);
        account::create_account_for_test(test_address);

        // Set up timestamp for testing
        let aptos_framework = account::create_account_for_test(@aptos_framework);
        timestamp::set_time_has_started_for_testing(&aptos_framework);

        // Initialize the module
        init_module(account);
        pause(account);

        let expected_resource_account_address = account::create_resource_address(&account_address, SEED);

        let usdc_address = @0xbae207659db88bea0cbead6da0ed00aac12edcdda169e591cd41c94180b46f3b;
        let amount = 1000;
        let rate = 1560;
        let message_hash = string::utf8(b"order created");
        let sender_fee_address = @0x03;
        let sender_fee = 3;
        let aggregator_addr = @0x04;
        let treasury_addr = @0x05;

        setting_manager_bool(account, string::utf8(b"token"), usdc_address, 1);
        update_protocol_address(account, string::utf8(b"treasury"), treasury_addr);
        update_protocol_address(account, string::utf8(b"aggregator"), aggregator_addr);

        create_order(test_user, usdc_address, amount, rate, sender_fee_address, sender_fee, @0x0, message_hash);

        let gateway = borrow_global<GatewaySettings>(expected_resource_account_address);
        assert!(vector::length(&gateway.supported_tokens) == 1, 1);
        assert!(vector::length(&gateway.order_store) == 0, 1);
        assert!(event::counter(&gateway.order_created_events) == 0, 1);
    }


    #[test(account = @gateway, test_user = @0x2)]
    #[expected_failure(abort_code = E_PAUSED)]
    public fun test_create_order_unsupported_token(
        account: &signer,
        test_user: &signer
    ) acquires GatewaySettings {
        let account_address = signer::address_of(account);
        let test_address = signer::address_of(test_user);
        account::create_account_for_test(account_address);
        account::create_account_for_test(test_address);

        // Set up timestamp for testing
        let aptos_framework = account::create_account_for_test(@aptos_framework);
        timestamp::set_time_has_started_for_testing(&aptos_framework);

        // Initialize the module
        init_module(account);
        pause(account);

        let expected_resource_account_address = account::create_resource_address(&account_address, SEED);

        let usdc_address = @0xbae207659db88bea0cbead6da0ed00aac12edcdda169e591cd41c94180b46f3b;
        let amount = 1000;
        let rate = 1560;
        let message_hash = string::utf8(b"order created");
        let sender_fee_address = @0x03;
        let sender_fee = 3;
        let aggregator_addr = @0x04;
        let treasury_addr = @0x05;

        setting_manager_bool(account, string::utf8(b"token"), @0x06, 1);
        update_protocol_address(account, string::utf8(b"treasury"), treasury_addr);
        update_protocol_address(account, string::utf8(b"aggregator"), aggregator_addr);

        create_order(test_user, usdc_address, amount, rate, sender_fee_address, sender_fee, @0x0, message_hash);

        let gateway = borrow_global<GatewaySettings>(expected_resource_account_address);
        assert!(vector::length(&gateway.supported_tokens) == 1, 1);
        assert!(vector::length(&gateway.order_store) == 0, 1);
        assert!(event::counter(&gateway.order_created_events) == 0, 1);
    }

    #[test(account = @gateway, test_user = @0x2)]
    public fun test_create_order_success(
        account: &signer,
        test_user: &signer
    ) acquires GatewaySettings {

        let account_address = signer::address_of(account);
        let test_address = signer::address_of(test_user);
        account::create_account_for_test(account_address);
        account::create_account_for_test(test_address);

        // Set up timestamp for testing
        let aptos_framework = account::create_account_for_test(@aptos_framework);
        timestamp::set_time_has_started_for_testing(&aptos_framework);

        // Initialize the module
        init_module(account);

        let expected_resource_account_address = account::create_resource_address(&account_address, SEED);

        // Create USDC metadata object
        let usdc_metadata_ref = object::create_named_object(test_user, b"USDC");
        primary_fungible_store::create_primary_store_enabled_fungible_asset(
            &usdc_metadata_ref,
            option::none(), // No maximum supply
            string::utf8(b"USD Coin"), // name
            string::utf8(b"USDC"), // symbol
            6, // decimals for USDC
            string::utf8(b"https://mock.png"), // icon_uri
            string::utf8(b"https://mock.com") // project_uri
        );

        let usdc_address = object::create_object_address(&test_address, b"USDC");
        let token_metadata = object::address_to_object<fungible_asset::Metadata>(usdc_address);

        // Generate MintRef and mint 10000 USDC to test_user's primary store
        let mint_ref = fungible_asset::generate_mint_ref(&usdc_metadata_ref);
        let to = primary_fungible_store::ensure_primary_store_exists(test_address, token_metadata);
        fungible_asset::mint_to(&mint_ref, to, (10000 * TOKEN_BASE));

        setting_manager_bool(account, string::utf8(b"token"), usdc_address, 1);

        let before_call_amount_for_caller = primary_fungible_store::balance(test_address, token_metadata);
        print(&before_call_amount_for_caller);
        let before_call_amount_for_resource_addr = primary_fungible_store::balance(expected_resource_account_address, token_metadata);

        let amount = 1000;
        let rate = 1560;
        let sender_fee_address = @0x03;
        let sender_fee = 3;
        let message_hash = string::utf8(b"order created");
        let aggregator_addr = @0x04;
        let treasury_addr = @0x05;

        setting_manager_bool(account, string::utf8(b"token"), usdc_address, 1);
        update_protocol_address(account, string::utf8(b"treasury"), treasury_addr);
        update_protocol_address(account, string::utf8(b"aggregator"), aggregator_addr);

        create_order(test_user, usdc_address, amount, rate, sender_fee_address, sender_fee, test_address, message_hash);

        let after_call_amount_for_caller = primary_fungible_store::balance(test_address, token_metadata);
        let after_call_amount_for_sender_fee_reciepient = primary_fungible_store::balance(sender_fee_address, token_metadata);
        let after_call_amount_for_resource_addr = primary_fungible_store::balance(expected_resource_account_address, token_metadata);

        let gateway = borrow_global<GatewaySettings>(expected_resource_account_address);
        assert!(gateway.paused == false, 0);

        assert!(before_call_amount_for_caller > after_call_amount_for_caller, 1);
        assert!(before_call_amount_for_resource_addr < after_call_amount_for_resource_addr, 1);
        assert!(after_call_amount_for_caller == (before_call_amount_for_caller - (amount * TOKEN_BASE_TENTH) - (sender_fee * TOKEN_BASE_TENTH)), 1);
        assert!(after_call_amount_for_resource_addr == ((amount * TOKEN_BASE_TENTH) + (sender_fee * TOKEN_BASE_TENTH)), 1);
        assert!(vector::length(&gateway.order_store) == 1, 1);
        assert!(event::counter(&gateway.order_created_events) == 1, 1);
    }

    #[test(account = @gateway, test_user = @0x2, aggregator = @0x4)]
    public fun test_settle_success_not_fully_fulfilled(
        account: &signer,
        test_user: &signer,
        aggregator: &signer
    ) acquires GatewaySettings, SignerCapabilityStore {

        let account_address = signer::address_of(account);
        let test_address = signer::address_of(test_user);
        let aggregator_address = signer::address_of(aggregator);
        account::create_account_for_test(account_address);
        account::create_account_for_test(test_address);
        account::create_account_for_test(aggregator_address);
        account::create_account_for_test(@0x03); // sender_fee_recipient
        account::create_account_for_test(@0x05); // treasury_address

        // Set up timestamp for testing
        let aptos_framework = account::create_account_for_test(@aptos_framework);
        timestamp::set_time_has_started_for_testing(&aptos_framework);

        // Initialize the module
        init_module(account);

        let expected_resource_account_address = account::create_resource_address(&account_address, SEED);

        // Create USDC metadata object
        let usdc_metadata_ref = object::create_named_object(test_user, b"USDC");
        primary_fungible_store::create_primary_store_enabled_fungible_asset(
            &usdc_metadata_ref,
            option::none(),
            string::utf8(b"USD Coin"),
            string::utf8(b"USDC"),
            6,
            string::utf8(b"https://mock.png"),
            string::utf8(b"https://mock.com")
        );

        let usdc_address = object::create_object_address(&test_address, b"USDC");
        let token_metadata = object::address_to_object<fungible_asset::Metadata>(usdc_address);

        // Mint 10000 USDC to test_user
        let mint_ref = fungible_asset::generate_mint_ref(&usdc_metadata_ref);
        let to = primary_fungible_store::ensure_primary_store_exists(test_address, token_metadata);
        fungible_asset::mint_to(&mint_ref, to, (10000 * TOKEN_BASE));

        // Set up protocol addresses and supported token
        setting_manager_bool(account, string::utf8(b"token"), usdc_address, 1);
        update_protocol_address(account, string::utf8(b"treasury"), @0x05);
        update_protocol_address(account, string::utf8(b"aggregator"), aggregator_address);

        // Create an order
        let amount = 1000;
        let rate = 1560;
        let sender_fee_address = @0x03;
        let sender_fee = 3;
        let message_hash = string::utf8(b"order created");
        create_order(test_user, usdc_address, amount, rate, sender_fee_address, sender_fee, test_address, message_hash);

        // Get order_id
        let gateway = borrow_global<GatewaySettings>(expected_resource_account_address);
        let order = vector::borrow(&gateway.order_store, 0);
        let order_id = order.order_id;
        let split_order_id = hash::sha3_256(bcs::to_bytes(&@0x123)); // Mock split_order_id

        // Balances before settle
        let before_settle_treasury_balance = primary_fungible_store::balance(@0x05, token_metadata);
        let before_settle_resource_balance = primary_fungible_store::balance(expected_resource_account_address, token_metadata);

        // Settle the order (50% settlement)
        let settle_percent = 50; // 50% in BPS
        let liquidity_provider = @0x06;
        account::create_account_for_test(liquidity_provider);

        let before_settle_order_amount = order.amount;
        settle(aggregator, split_order_id, order_id, liquidity_provider, settle_percent);

        // Verify state after settle
        let gateway = borrow_global<GatewaySettings>(expected_resource_account_address);
        let order = vector::borrow(&gateway.order_store, 0);
        let expected_liquidity_provider_amount = (before_settle_order_amount * (settle_percent * BASE_BPS)) / MAX_BPS;
        let expected_remaining_amount = before_settle_order_amount - expected_liquidity_provider_amount;

        assert!(order.current_bps == MAX_BPS - (settle_percent * BASE_BPS), 1);
        assert!(order.amount == expected_remaining_amount, 2);
        assert!(order.is_fulfilled == false, 1);
        assert!(event::counter(&gateway.order_settled_events) == 1, 4);
        assert!(primary_fungible_store::balance(@0x05, token_metadata) == before_settle_treasury_balance, 5);
        assert!(primary_fungible_store::balance(liquidity_provider, token_metadata) == expected_remaining_amount, 6);
        assert!(primary_fungible_store::balance(expected_resource_account_address, token_metadata) == (before_settle_resource_balance - expected_liquidity_provider_amount), 7);
    }

    #[test(account = @gateway, test_user = @0x2, aggregator = @0x4)]
    public fun test_settle_success(
        account: &signer,
        test_user: &signer,
        aggregator: &signer
    ) acquires GatewaySettings, SignerCapabilityStore {

        let account_address = signer::address_of(account);
        let test_address = signer::address_of(test_user);
        let aggregator_address = signer::address_of(aggregator);
        account::create_account_for_test(account_address);
        account::create_account_for_test(test_address);
        account::create_account_for_test(aggregator_address);
        account::create_account_for_test(@0x03); // sender_fee_recipient
        account::create_account_for_test(@0x05); // treasury_address

        // Set up timestamp for testing
        let aptos_framework = account::create_account_for_test(@aptos_framework);
        timestamp::set_time_has_started_for_testing(&aptos_framework);

        // Initialize the module
        init_module(account);

        let expected_resource_account_address = account::create_resource_address(&account_address, SEED);

        // Create USDC metadata object
        let usdc_metadata_ref = object::create_named_object(test_user, b"USDC");
        primary_fungible_store::create_primary_store_enabled_fungible_asset(
            &usdc_metadata_ref,
            option::none(),
            string::utf8(b"USD Coin"),
            string::utf8(b"USDC"),
            6,
            string::utf8(b"https://mock.png"),
            string::utf8(b"https://mock.com")
        );

        let usdc_address = object::create_object_address(&test_address, b"USDC");
        let token_metadata = object::address_to_object<fungible_asset::Metadata>(usdc_address);

        // Mint 10000 USDC to test_user
        let mint_ref = fungible_asset::generate_mint_ref(&usdc_metadata_ref);
        let to = primary_fungible_store::ensure_primary_store_exists(test_address, token_metadata);
        fungible_asset::mint_to(&mint_ref, to, (10000 * TOKEN_BASE));

        // Set up protocol addresses and supported token
        setting_manager_bool(account, string::utf8(b"token"), usdc_address, 1);
        update_protocol_address(account, string::utf8(b"treasury"), @0x05);
        update_protocol_address(account, string::utf8(b"aggregator"), aggregator_address);

        // Create an order
        let amount = 1000;
        let rate = 1560;
        let sender_fee_address = @0x03;
        let sender_fee = 3;
        let message_hash = string::utf8(b"order created");
        create_order(test_user, usdc_address, amount, rate, sender_fee_address, sender_fee, test_address, message_hash);

        // Get order_id
        let gateway = borrow_global<GatewaySettings>(expected_resource_account_address);
        let order = vector::borrow(&gateway.order_store, 0);
        let order_id = order.order_id;
        let split_order_id = hash::sha3_256(bcs::to_bytes(&@0x123)); // Mock split_order_id

        // Balances before settle
        let before_sender_fee_receipient_balance =  primary_fungible_store::balance(sender_fee_address, token_metadata);
        let before_settle_treasury_balance = primary_fungible_store::balance(@0x05, token_metadata);
        let before_settle_resource_balance = primary_fungible_store::balance(expected_resource_account_address, token_metadata);

        // Settle the order (50% settlement)
        let settle_percent = 100; // 50% in BPS
        let liquidity_provider = @0x06;
        account::create_account_for_test(liquidity_provider);

        let before_settle_order_amount = order.amount;
        settle(aggregator, split_order_id, order_id, liquidity_provider, settle_percent);

        // Verify state after settle
        let gateway = borrow_global<GatewaySettings>(expected_resource_account_address);
        let order = vector::borrow(&gateway.order_store, 0);
        let expected_liquidity_provider_amount = (before_settle_order_amount * (settle_percent * BASE_BPS)) / MAX_BPS;
        let expected_remaining_amount = before_settle_order_amount - expected_liquidity_provider_amount;

        print(&(before_settle_treasury_balance + expected_liquidity_provider_amount));
        print(&primary_fungible_store::balance(@0x05, token_metadata));
        print(&before_settle_treasury_balance);

        assert!(order.current_bps == MAX_BPS - (settle_percent * BASE_BPS), 1);
        assert!(order.amount == expected_remaining_amount, 2);
        assert!(order.is_fulfilled == true, 1);
        assert!(event::counter(&gateway.order_settled_events) == 1, 4);
        assert!(primary_fungible_store::balance(@0x05, token_metadata) == before_settle_treasury_balance + order.protocol_fee, 5);
        assert!(primary_fungible_store::balance(sender_fee_address, token_metadata) == before_sender_fee_receipient_balance + (sender_fee * TOKEN_BASE_TENTH), 5);
        assert!(primary_fungible_store::balance(liquidity_provider, token_metadata) == expected_liquidity_provider_amount, 6);
        assert!(primary_fungible_store::balance(expected_resource_account_address, token_metadata) == (before_settle_resource_balance - expected_liquidity_provider_amount - (sender_fee * TOKEN_BASE_TENTH)), 6);
    }

    #[test(account = @gateway, test_user = @0x2, aggregator = @0x4)]
    #[expected_failure(abort_code = E_NOT_AGGREGATOR)]
    public fun test_settle_not_aggregator(
        account: &signer,
        test_user: &signer,
        aggregator: &signer
    ) acquires GatewaySettings, SignerCapabilityStore {

        let account_address = signer::address_of(account);
        let test_address = signer::address_of(test_user);
        let aggregator_address = signer::address_of(aggregator);
        account::create_account_for_test(account_address);
        account::create_account_for_test(test_address);
        account::create_account_for_test(aggregator_address);
        account::create_account_for_test(@0x03); // sender_fee_recipient
        account::create_account_for_test(@0x05); // treasury_address

        // Set up timestamp for testing
        let aptos_framework = account::create_account_for_test(@aptos_framework);
        timestamp::set_time_has_started_for_testing(&aptos_framework);

        // Initialize the module
        init_module(account);

        let expected_resource_account_address = account::create_resource_address(&account_address, SEED);

        // Create USDC metadata object
        let usdc_metadata_ref = object::create_named_object(test_user, b"USDC");
        primary_fungible_store::create_primary_store_enabled_fungible_asset(
            &usdc_metadata_ref,
            option::none(),
            string::utf8(b"USD Coin"),
            string::utf8(b"USDC"),
            6,
            string::utf8(b"https://mock.png"),
            string::utf8(b"https://mock.com")
        );

        let usdc_address = object::create_object_address(&test_address, b"USDC");
        let token_metadata = object::address_to_object<fungible_asset::Metadata>(usdc_address);

        // Mint 10000 USDC to test_user
        let mint_ref = fungible_asset::generate_mint_ref(&usdc_metadata_ref);
        let to = primary_fungible_store::ensure_primary_store_exists(test_address, token_metadata);
        fungible_asset::mint_to(&mint_ref, to, (10000 * TOKEN_BASE));

        // Set up protocol addresses and supported token
        setting_manager_bool(account, string::utf8(b"token"), usdc_address, 1);
        update_protocol_address(account, string::utf8(b"treasury"), @0x05);
        update_protocol_address(account, string::utf8(b"aggregator"), @0x07); // Different aggregator

        // Create an order
        let amount = 1000;
        let rate = 1560;
        let sender_fee_address = @0x03;
        let sender_fee = 3;
        let message_hash = string::utf8(b"order created");
        create_order(test_user, usdc_address, amount, rate, sender_fee_address, sender_fee, test_address, message_hash);

        // Get order_id
        let gateway = borrow_global<GatewaySettings>(expected_resource_account_address);
        let order = vector::borrow(&gateway.order_store, 0);
        let order_id = order.order_id;
        let split_order_id = hash::sha3_256(bcs::to_bytes(&@0x123));

        // Attempt to settle with non-aggregator account
        settle(test_user, split_order_id, order_id, @0x06, 5000);

        // Verify no state changes
        let gateway = borrow_global<GatewaySettings>(expected_resource_account_address);
        assert!(vector::length(&gateway.order_store) == 1, 1);
        assert!(event::counter(&gateway.order_settled_events) == 0, 2);
    }

    #[test(account = @gateway, test_user = @0x2, aggregator = @0x4)]
    #[expected_failure(abort_code = E_ORDER_FULFILLED)]
    public fun test_settle_order_already_fulfilled(
        account: &signer,
        test_user: &signer,
        aggregator: &signer
    ) acquires GatewaySettings, SignerCapabilityStore {

        let account_address = signer::address_of(account);
        let test_address = signer::address_of(test_user);
        let aggregator_address = signer::address_of(aggregator);
        account::create_account_for_test(account_address);
        account::create_account_for_test(test_address);
        account::create_account_for_test(aggregator_address);
        account::create_account_for_test(@0x03);
        account::create_account_for_test(@0x05);

        // Set up timestamp for testing
        let aptos_framework = account::create_account_for_test(@aptos_framework);
        timestamp::set_time_has_started_for_testing(&aptos_framework);

        // Initialize the module
        init_module(account);

        let expected_resource_account_address = account::create_resource_address(&account_address, SEED);

        // Create USDC metadata object
        let usdc_metadata_ref = object::create_named_object(test_user, b"USDC");
        primary_fungible_store::create_primary_store_enabled_fungible_asset(
            &usdc_metadata_ref,
            option::none(),
            string::utf8(b"USD Coin"),
            string::utf8(b"USDC"),
            6,
            string::utf8(b"https://mock.png"),
            string::utf8(b"https://mock.com")
        );

        let usdc_address = object::create_object_address(&test_address, b"USDC");
        let token_metadata = object::address_to_object<fungible_asset::Metadata>(usdc_address);

        // Mint 10000 USDC to test_user
        let mint_ref = fungible_asset::generate_mint_ref(&usdc_metadata_ref);
        let to = primary_fungible_store::ensure_primary_store_exists(test_address, token_metadata);
        fungible_asset::mint_to(&mint_ref, to, (10000 * TOKEN_BASE));

        // Set up protocol addresses and supported token
        setting_manager_bool(account, string::utf8(b"token"), usdc_address, 1);
        update_protocol_address(account, string::utf8(b"treasury"), @0x05);
        update_protocol_address(account, string::utf8(b"aggregator"), aggregator_address);

        // Create an order
        let amount = 1000;
        let rate = 1560;
        let sender_fee_address = @0x03;
        let sender_fee = 3;
        let message_hash = string::utf8(b"order created");
        create_order(test_user, usdc_address, amount, rate, sender_fee_address, sender_fee, test_address, message_hash);

        // Get order_id
        let gateway = borrow_global<GatewaySettings>(expected_resource_account_address);
        let order = vector::borrow(&gateway.order_store, 0);
        let order_id = order.order_id;
        let split_order_id = hash::sha3_256(bcs::to_bytes(&@0x123));

        // Fully settle the order
        settle(aggregator, split_order_id, order_id, @0x06, 100);

        // Attempt to settle again
        settle(aggregator, split_order_id, order_id, @0x06, 10);

        // Verify no additional settlement events
        let gateway = borrow_global<GatewaySettings>(expected_resource_account_address);
        print(&event::counter(&gateway.order_settled_events));
        assert!(event::counter(&gateway.order_settled_events) == 1, 1);
    }

    #[test(account = @gateway, test_user = @0x2, aggregator = @0x4)]
    #[expected_failure(abort_code = E_ORDER_REFUNDED)]
    public fun test_settle_order_already_refunded(
        account: &signer,
        test_user: &signer,
        aggregator: &signer
    ) acquires GatewaySettings, SignerCapabilityStore {
       

        let account_address = signer::address_of(account);
        let test_address = signer::address_of(test_user);
        let aggregator_address = signer::address_of(aggregator);
        account::create_account_for_test(account_address);
        account::create_account_for_test(test_address);
        account::create_account_for_test(aggregator_address);
        account::create_account_for_test(@0x03);
        account::create_account_for_test(@0x05);

        // Set up timestamp for testing
        let aptos_framework = account::create_account_for_test(@aptos_framework);
        timestamp::set_time_has_started_for_testing(&aptos_framework);

        // Initialize the module
        init_module(account);

        let expected_resource_account_address = account::create_resource_address(&account_address, SEED);

        // Create USDC metadata object
        let usdc_metadata_ref = object::create_named_object(test_user, b"USDC");
        primary_fungible_store::create_primary_store_enabled_fungible_asset(
            &usdc_metadata_ref,
            option::none(),
            string::utf8(b"USD Coin"),
            string::utf8(b"USDC"),
            6,
            string::utf8(b"https://mock.png"),
            string::utf8(b"https://mock.com")
        );

        let usdc_address = object::create_object_address(&test_address, b"USDC");
        let token_metadata = object::address_to_object<fungible_asset::Metadata>(usdc_address);

        // Mint 10000 USDC to test_user
        let mint_ref = fungible_asset::generate_mint_ref(&usdc_metadata_ref);
        let to = primary_fungible_store::ensure_primary_store_exists(test_address, token_metadata);
        fungible_asset::mint_to(&mint_ref, to, (10000 * TOKEN_BASE));

        // Set up protocol addresses and supported token
        setting_manager_bool(account, string::utf8(b"token"), usdc_address, 1);
        update_protocol_address(account, string::utf8(b"treasury"), @0x05);
        update_protocol_address(account, string::utf8(b"aggregator"), aggregator_address);

        // Create an order
        let amount = 1000;
        let rate = 1560;
        let sender_fee_address = @0x03;
        let sender_fee = 3;
        let message_hash = string::utf8(b"order created");
        create_order(test_user, usdc_address, amount, rate, sender_fee_address, sender_fee, test_address, message_hash);

        // Get order_id
        let gateway = borrow_global<GatewaySettings>(expected_resource_account_address);
        let order = vector::borrow(&gateway.order_store, 0);
        let order_id = order.order_id;
        let split_order_id = hash::sha3_256(bcs::to_bytes(&@0x123));

        // Refund the order
        refund(aggregator, 0, order_id);

        // Attempt to settle
        settle(aggregator, split_order_id, order_id, @0x06, (100 * BASE_BPS));

        // Verify no settlement events
        let gateway = borrow_global<GatewaySettings>(expected_resource_account_address);
        assert!(event::counter(&gateway.order_settled_events) == 0, 1);
        assert!(event::counter(&gateway.order_refunded_events) == 1, 1);
    }

    #[test(account = @gateway, test_user = @0x2, aggregator = @0x4)]
    public fun test_refund_success(
        account: &signer,
        test_user: &signer,
        aggregator: &signer
    ) acquires GatewaySettings, SignerCapabilityStore {

        let account_address = signer::address_of(account);
        let test_address = signer::address_of(test_user);
        let aggregator_address = signer::address_of(aggregator);
        account::create_account_for_test(account_address);
        account::create_account_for_test(test_address);
        account::create_account_for_test(aggregator_address);
        account::create_account_for_test(@0x03);
        account::create_account_for_test(@0x05);

        // Set up timestamp for testing
        let aptos_framework = account::create_account_for_test(@aptos_framework);
        timestamp::set_time_has_started_for_testing(&aptos_framework);

        // Initialize the module
        init_module(account);

        let expected_resource_account_address = account::create_resource_address(&account_address, SEED);

        // Create USDC metadata object
        let usdc_metadata_ref = object::create_named_object(test_user, b"USDC");
        primary_fungible_store::create_primary_store_enabled_fungible_asset(
            &usdc_metadata_ref,
            option::none(),
            string::utf8(b"USD Coin"),
            string::utf8(b"USDC"),
            6,
            string::utf8(b"https://mock.png"),
            string::utf8(b"https://mock.com")
        );

        let usdc_address = object::create_object_address(&test_address, b"USDC");
        let token_metadata = object::address_to_object<fungible_asset::Metadata>(usdc_address);

        // Mint 10000 USDC to test_user
        let mint_ref = fungible_asset::generate_mint_ref(&usdc_metadata_ref);
        let to = primary_fungible_store::ensure_primary_store_exists(test_address, token_metadata);
        fungible_asset::mint_to(&mint_ref, to, (10000 * TOKEN_BASE));

        // Set up protocol addresses and supported token
        setting_manager_bool(account, string::utf8(b"token"), usdc_address, 1);
        update_protocol_address(account, string::utf8(b"treasury"), @0x05);
        update_protocol_address(account, string::utf8(b"aggregator"), aggregator_address);

        // Create an order
        let amount = 1000;
        let rate = 1560;
        let sender_fee_address = @0x03;
        let sender_fee = 3;
        let message_hash = string::utf8(b"order created");
        create_order(test_user, usdc_address, amount, rate, sender_fee_address, sender_fee, test_address, message_hash);

        // Get order_id
        let gateway = borrow_global<GatewaySettings>(expected_resource_account_address);
        let order = vector::borrow(&gateway.order_store, 0);
        let order_id = order.order_id;

        // Balances before refund
        let before_refund_refund_address_balance = primary_fungible_store::balance(test_address, token_metadata);
        let before_refund_treasury_balance = primary_fungible_store::balance(@0x05, token_metadata);
        let before_refund_resource_balance = primary_fungible_store::balance(expected_resource_account_address, token_metadata);

        // Refund the order
        let fee = 0;
        refund(aggregator, fee, order_id);

        // Verify state after refund
        let gateway = borrow_global<GatewaySettings>(expected_resource_account_address);
        let order = vector::borrow(&gateway.order_store, 0);
        let expected_refunded_amount = order.amount + order.protocol_fee - fee + order.sender_fee;

        assert!(order.is_refunded == true, 1);
        assert!(order.current_bps == 0, 2);
        assert!(event::counter(&gateway.order_refunded_events) == 1, 3);
        assert!(primary_fungible_store::balance(test_address, token_metadata) == before_refund_refund_address_balance + expected_refunded_amount, 4);
        assert!(primary_fungible_store::balance(@0x05, token_metadata) == before_refund_treasury_balance + fee, 5);
        assert!(primary_fungible_store::balance(expected_resource_account_address, token_metadata) == before_refund_resource_balance - expected_refunded_amount - fee, 6);
    }

    #[test(account = @gateway, test_user = @0x2, aggregator = @0x4)]
    #[expected_failure(abort_code = E_NOT_AGGREGATOR)]
    public fun test_refund_not_aggregator(
        account: &signer,
        test_user: &signer,
        aggregator: &signer
    ) acquires GatewaySettings, SignerCapabilityStore {
       

        let account_address = signer::address_of(account);
        let test_address = signer::address_of(test_user);
        let aggregator_address = signer::address_of(aggregator);
        account::create_account_for_test(account_address);
        account::create_account_for_test(test_address);
        account::create_account_for_test(aggregator_address);
        account::create_account_for_test(@0x03);
        account::create_account_for_test(@0x05);

        // Set up timestamp for testing
        let aptos_framework = account::create_account_for_test(@aptos_framework);
        timestamp::set_time_has_started_for_testing(&aptos_framework);

        // Initialize the module
        init_module(account);

        let expected_resource_account_address = account::create_resource_address(&account_address, SEED);

        // Create USDC metadata object
        let usdc_metadata_ref = object::create_named_object(test_user, b"USDC");
        primary_fungible_store::create_primary_store_enabled_fungible_asset(
            &usdc_metadata_ref,
            option::none(),
            string::utf8(b"USD Coin"),
            string::utf8(b"USDC"),
            6,
            string::utf8(b"https://mock.png"),
            string::utf8(b"https://mock.com")
        );

        let usdc_address = object::create_object_address(&test_address, b"USDC");
        let token_metadata = object::address_to_object<fungible_asset::Metadata>(usdc_address);

        // Mint 10000 USDC to test_user
        let mint_ref = fungible_asset::generate_mint_ref(&usdc_metadata_ref);
        let to = primary_fungible_store::ensure_primary_store_exists(test_address, token_metadata);
        fungible_asset::mint_to(&mint_ref, to, (10000 * TOKEN_BASE));

        // Set up protocol addresses and supported token
        setting_manager_bool(account, string::utf8(b"token"), usdc_address, 1);
        update_protocol_address(account, string::utf8(b"treasury"), @0x05);
        update_protocol_address(account, string::utf8(b"aggregator"), @0x07); // Different aggregator

        // Create an order
        let amount = 1000;
        let rate = 1560;
        let sender_fee_address = @0x03;
        let sender_fee = 3;
        let message_hash = string::utf8(b"order created");
        create_order(test_user, usdc_address, amount, rate, sender_fee_address, sender_fee, test_address, message_hash);

        // Get order_id
        let gateway = borrow_global<GatewaySettings>(expected_resource_account_address);
        let order = vector::borrow(&gateway.order_store, 0);
        let order_id = order.order_id;

        // Attempt to refund with non-aggregator account
        refund(test_user, 0, order_id);

        // Verify no state changes
        let gateway = borrow_global<GatewaySettings>(expected_resource_account_address);
        assert!(vector::length(&gateway.order_store) == 1, 1);
        assert!(event::counter(&gateway.order_refunded_events) == 0, 2);
    }


    #[test(account = @gateway, test_user = @0x2, aggregator = @0x4)]
    #[expected_failure(abort_code = E_ORDER_FULFILLED)]
    public fun test_refund_order_already_fulfilled(
        account: &signer,
        test_user: &signer,
        aggregator: &signer
    ) acquires GatewaySettings, SignerCapabilityStore {

        let account_address = signer::address_of(account);
        let test_address = signer::address_of(test_user);
        let aggregator_address = signer::address_of(aggregator);
        account::create_account_for_test(account_address);
        account::create_account_for_test(test_address);
        account::create_account_for_test(aggregator_address);
        account::create_account_for_test(@0x03);
        account::create_account_for_test(@0x05);

        // Set up timestamp for testing
        let aptos_framework = account::create_account_for_test(@aptos_framework);
        timestamp::set_time_has_started_for_testing(&aptos_framework);

        // Initialize the module
        init_module(account);

        let expected_resource_account_address = account::create_resource_address(&account_address, SEED);

        // Create USDC metadata object
        let usdc_metadata_ref = object::create_named_object(test_user, b"USDC");
        primary_fungible_store::create_primary_store_enabled_fungible_asset(
            &usdc_metadata_ref,
            option::none(),
            string::utf8(b"USD Coin"),
            string::utf8(b"USDC"),
            6,
            string::utf8(b"https://mock.png"),
            string::utf8(b"https://mock.com")
        );

        let usdc_address = object::create_object_address(&test_address, b"USDC");
        let token_metadata = object::address_to_object<fungible_asset::Metadata>(usdc_address);

        // Mint 10000 USDC to test_user
        let mint_ref = fungible_asset::generate_mint_ref(&usdc_metadata_ref);
        let to = primary_fungible_store::ensure_primary_store_exists(test_address, token_metadata);
        fungible_asset::mint_to(&mint_ref, to, (10000 * TOKEN_BASE));

        // Set up protocol addresses and supported token
        setting_manager_bool(account, string::utf8(b"token"), usdc_address, 1);
        update_protocol_address(account, string::utf8(b"treasury"), @0x05);
        update_protocol_address(account, string::utf8(b"aggregator"), aggregator_address);

        // Create an order
        let amount = 1000;
        let rate = 1560;
        let sender_fee_address = @0x03;
        let sender_fee = 3;
        let message_hash = string::utf8(b"order created");
        create_order(test_user, usdc_address, amount, rate, sender_fee_address, sender_fee, test_address, message_hash);

        // Get order_id
        let gateway = borrow_global<GatewaySettings>(expected_resource_account_address);
        let order = vector::borrow(&gateway.order_store, 0);
        let order_id = order.order_id;
        let split_order_id = hash::sha3_256(bcs::to_bytes(&@0x123));

        // Fully settle the order
        settle(aggregator, split_order_id, order_id, @0x06, 100);

        // Attempt to refund
        refund(aggregator, 0, order_id);

        // Verify no refund events
        let gateway = borrow_global<GatewaySettings>(expected_resource_account_address);

        print(&event::counter(&gateway.order_refunded_events));
        assert!(event::counter(&gateway.order_settled_events) == 1, 1);
        assert!(event::counter(&gateway.order_refunded_events) == 0, 1);
    }

    #[test(account = @gateway, test_user = @0x2, aggregator = @0x4)]
    public fun test_refund_order_already_not_fully_settled(
        account: &signer,
        test_user: &signer,
        aggregator: &signer
    ) acquires GatewaySettings, SignerCapabilityStore {

        let account_address = signer::address_of(account);
        let test_address = signer::address_of(test_user);
        let aggregator_address = signer::address_of(aggregator);
        account::create_account_for_test(account_address);
        account::create_account_for_test(test_address);
        account::create_account_for_test(aggregator_address);
        account::create_account_for_test(@0x03);
        account::create_account_for_test(@0x05);

        // Set up timestamp for testing
        let aptos_framework = account::create_account_for_test(@aptos_framework);
        timestamp::set_time_has_started_for_testing(&aptos_framework);

        // Initialize the module
        init_module(account);

        let expected_resource_account_address = account::create_resource_address(&account_address, SEED);

        // Create USDC metadata object
        let usdc_metadata_ref = object::create_named_object(test_user, b"USDC");
        primary_fungible_store::create_primary_store_enabled_fungible_asset(
            &usdc_metadata_ref,
            option::none(),
            string::utf8(b"USD Coin"),
            string::utf8(b"USDC"),
            6,
            string::utf8(b"https://mock.png"),
            string::utf8(b"https://mock.com")
        );

        let usdc_address = object::create_object_address(&test_address, b"USDC");
        let token_metadata = object::address_to_object<fungible_asset::Metadata>(usdc_address);

        // Mint 10000 USDC to test_user
        let mint_ref = fungible_asset::generate_mint_ref(&usdc_metadata_ref);
        let to = primary_fungible_store::ensure_primary_store_exists(test_address, token_metadata);
        fungible_asset::mint_to(&mint_ref, to, (10000 * TOKEN_BASE));

        // Set up protocol addresses and supported token
        setting_manager_bool(account, string::utf8(b"token"), usdc_address, 1);
        update_protocol_address(account, string::utf8(b"treasury"), @0x05);
        update_protocol_address(account, string::utf8(b"aggregator"), aggregator_address);

        // Create an order
        let amount = 1000;
        let rate = 1560;
        let sender_fee_address = @0x03;
        let sender_fee = 3;
        let message_hash = string::utf8(b"order created");
        create_order(test_user, usdc_address, amount, rate, sender_fee_address, sender_fee, test_address, message_hash);

        // Get order_id
        let gateway = borrow_global<GatewaySettings>(expected_resource_account_address);
        let order = vector::borrow(&gateway.order_store, 0);
        let order_id = order.order_id;
        let split_order_id = hash::sha3_256(bcs::to_bytes(&@0x123));

        // Dont Fully settle the order
        settle(aggregator, split_order_id, order_id, @0x06, 50);

        // Attempt to refund
        refund(aggregator, 0, order_id);

        // Verify no refund events
        let gateway = borrow_global<GatewaySettings>(expected_resource_account_address);

        print(&event::counter(&gateway.order_refunded_events));
        assert!(event::counter(&gateway.order_settled_events) == 1, 1);
        assert!(event::counter(&gateway.order_refunded_events) == 1, 1);
    }

    #[test(account = @gateway, test_user = @0x2, aggregator = @0x4)]
    #[expected_failure(abort_code = E_ORDER_REFUNDED)]
    public fun test_refund_order_already_refunded(
        account: &signer,
        test_user: &signer,
        aggregator: &signer
    ) acquires GatewaySettings, SignerCapabilityStore {

        let account_address = signer::address_of(account);
        let test_address = signer::address_of(test_user);
        let aggregator_address = signer::address_of(aggregator);
        account::create_account_for_test(account_address);
        account::create_account_for_test(test_address);
        account::create_account_for_test(aggregator_address);
        account::create_account_for_test(@0x03);
        account::create_account_for_test(@0x05);

        // Set up timestamp for testing
        let aptos_framework = account::create_account_for_test(@aptos_framework);
        timestamp::set_time_has_started_for_testing(&aptos_framework);

        // Initialize the module
        init_module(account);

        let expected_resource_account_address = account::create_resource_address(&account_address, SEED);

        // Create USDC metadata object
        let usdc_metadata_ref = object::create_named_object(test_user, b"USDC");
        primary_fungible_store::create_primary_store_enabled_fungible_asset(
            &usdc_metadata_ref,
            option::none(),
            string::utf8(b"USD Coin"),
            string::utf8(b"USDC"),
            6,
            string::utf8(b"https://mock.png"),
            string::utf8(b"https://mock.com")
        );

        let usdc_address = object::create_object_address(&test_address, b"USDC");
        let token_metadata = object::address_to_object<fungible_asset::Metadata>(usdc_address);

        // Mint 10000 USDC to test_user
        let mint_ref = fungible_asset::generate_mint_ref(&usdc_metadata_ref);
        let to = primary_fungible_store::ensure_primary_store_exists(test_address, token_metadata);
        fungible_asset::mint_to(&mint_ref, to, (10000 * TOKEN_BASE));

        // Set up protocol addresses and supported token
        setting_manager_bool(account, string::utf8(b"token"), usdc_address, 1);
        update_protocol_address(account, string::utf8(b"treasury"), @0x05);
        update_protocol_address(account, string::utf8(b"aggregator"), aggregator_address);

        // Create an order
        let amount = 1000;
        let rate = 1560;
        let sender_fee_address = @0x03;
        let sender_fee = 3;
        let message_hash = string::utf8(b"order created");
        create_order(test_user, usdc_address, amount, rate, sender_fee_address, sender_fee, test_address, message_hash);

        // Get order_id
        let gateway = borrow_global<GatewaySettings>(expected_resource_account_address);
        let order = vector::borrow(&gateway.order_store, 0);
        let order_id = order.order_id;

        // Refund the order
        refund(aggregator, 0, order_id);

        // Attempt to refund again
        refund(aggregator, 0, order_id);

        // Verify no additional refund events
        let gateway = borrow_global<GatewaySettings>(expected_resource_account_address);
        assert!(event::counter(&gateway.order_refunded_events) == 1, 1);
    }

    #[test(account = @gateway, test_user = @0x2, aggregator = @0x4)]
    #[expected_failure(abort_code = E_FEE_EXCEEDS_PROTOCOL)]
    public fun test_refund_fee_exceeds_protocol(
        account: &signer,
        test_user: &signer,
        aggregator: &signer
    ) acquires GatewaySettings, SignerCapabilityStore {

        let account_address = signer::address_of(account);
        let test_address = signer::address_of(test_user);
        let aggregator_address = signer::address_of(aggregator);
        account::create_account_for_test(account_address);
        account::create_account_for_test(test_address);
        account::create_account_for_test(aggregator_address);
        account::create_account_for_test(@0x03);
        account::create_account_for_test(@0x05);

        // Set up timestamp for testing
        let aptos_framework = account::create_account_for_test(@aptos_framework);
        timestamp::set_time_has_started_for_testing(&aptos_framework);

        // Initialize the module
        init_module(account);

        let expected_resource_account_address = account::create_resource_address(&account_address, SEED);

        // Create USDC metadata object
        let usdc_metadata_ref = object::create_named_object(test_user, b"USDC");
        primary_fungible_store::create_primary_store_enabled_fungible_asset(
            &usdc_metadata_ref,
            option::none(),
            string::utf8(b"USD Coin"),
            string::utf8(b"USDC"),
            6,
            string::utf8(b"https://mock.png"),
            string::utf8(b"https://mock.com")
        );

        let usdc_address = object::create_object_address(&test_address, b"USDC");
        let token_metadata = object::address_to_object<fungible_asset::Metadata>(usdc_address);

        // Mint 10000 USDC to test_user
        let mint_ref = fungible_asset::generate_mint_ref(&usdc_metadata_ref);
        let to = primary_fungible_store::ensure_primary_store_exists(test_address, token_metadata);
        fungible_asset::mint_to(&mint_ref, to, (10000 * TOKEN_BASE));

        // Set up protocol addresses and supported token
        setting_manager_bool(account, string::utf8(b"token"), usdc_address, 1);
        update_protocol_address(account, string::utf8(b"treasury"), @0x05);
        update_protocol_address(account, string::utf8(b"aggregator"), aggregator_address);

        // Create an order
        let amount = 1000;
        let rate = 1560;
        let sender_fee_address = @0x03;
        let sender_fee = 3;
        let message_hash = string::utf8(b"order created");
        create_order(test_user, usdc_address, amount, rate, sender_fee_address, sender_fee, test_address, message_hash);

        // Get order_id
        let gateway = borrow_global<GatewaySettings>(expected_resource_account_address);
        let order = vector::borrow(&gateway.order_store, 0);
        let order_id = order.order_id;

        // Attempt to refund with excessive fee
        let excessive_fee = order.amount + order.protocol_fee + 1;
        refund(aggregator, excessive_fee, order_id);

        // Verify no refund events
        let gateway = borrow_global<GatewaySettings>(expected_resource_account_address);
        assert!(event::counter(&gateway.order_refunded_events) == 0, 1);
    }
}