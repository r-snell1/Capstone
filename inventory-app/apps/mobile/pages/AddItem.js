import React, { useState } from 'react';
import { View, Text, TextInput, Button, StyleSheet } from 'react-native';
import { createItem } from '../../../packages/shared/api';

export default function AddItem({ navigation }) {
    const [name, setName] = useState('');
    const [quantity, setQuantity] = useState('');
    const [location, setLocation] = useState('');
    const [description, setDescription] = useState('');

    const handleSubmit = async () => {
        try {
            await createItem({ name, quantity: parseInt(quantity), location, description });
            navigation.goBack();
        } catch (err) {
            console.error('Failed to create item', err);
        }
    };

    return (
        <View style={styles.container}>
            <Text style={styles.title}>Add Item</Text>
            <TextInput style={styles.input} placeholder="Name" value={name} onChangeText={setName} />
            <TextInput style={styles.input} placeholder="Quantity" value={quantity} onChangeText={setQuantity} keyboardType="numeric" />
            <TextInput style={styles.input} placeholder="Location" value={location} onChangeText={setLocation} />
            <TextInput style={styles.input} placeholder="Description" value={description} onChangeText={setDescription} />
            <Button title="Save" onPress={handleSubmit} />
        </View>
    );
}

const styles = StyleSheet.create({
    container: { flex: 1, padding: 20, paddingTop: 50 },
    title: { fontSize: 24, fontWeight: 'bold', marginBottom: 20 },
    input: { borderBottomWidth: 1, marginBottom: 15, fontSize: 18, paddingVertical: 5 },
});