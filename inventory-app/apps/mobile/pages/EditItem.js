import React, { useState } from 'react';
import { View, Text, TextInput, Button, StyleSheet } from 'react-native';
import { updateItem } from '../../../packages/shared/api';

export default function EditItem({ route, navigation }) {
    const { item } = route.params;
    const [name, setName] = useState(item.name ?? '');
    const [quantity, setQuantity] = useState(item.quantity?.toString() ?? '');
    const [location, setLocation] = useState(item.location ?? '');
    const [description, setDescription] = useState(item.description ?? '');

    const handleUpdate = async () => {
        try {
            await updateItem(item._id, { name, quantity: parseInt(quantity), location, description });
            navigation.goBack();
        } catch (err) {
            console.error('Failed to update item', err);
        }
    };

    return (
        <View style={styles.container}>
            <Text style={styles.title}>Edit Item</Text>
            <TextInput style={styles.input} value={name} onChangeText={setName} />
            <TextInput style={styles.input} value={quantity} onChangeText={setQuantity} keyboardType="numeric" />
            <TextInput style={styles.input} value={location} onChangeText={setLocation} />
            <TextInput style={styles.input} value={description} onChangeText={setDescription} />
            <Button title="Save Changes" onPress={handleUpdate} />
        </View>
    );
}

const styles = StyleSheet.create({
    container: { flex: 1, padding: 20, paddingTop: 50 },
    title: { fontSize: 24, fontWeight: 'bold', marginBottom: 20 },
    input: { borderBottomWidth: 1, marginBottom: 15, fontSize: 18, paddingVertical: 5 },
});