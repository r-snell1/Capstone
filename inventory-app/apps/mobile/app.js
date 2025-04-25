import React, { useEffect, useState } from 'react';
import { View, Text } from 'react-native';
import axios from 'axios';

export default function App() {
    const [message, setMessage] = useState('Loading...');

    useEffect(() => {
        axios.get('http://<your-local-ip>:5000/')
            .then(res => setMessage(res.data))
            .catch(err => console.error(err));
    }, []);

    return (
        <View style={{ marginTop: 50 }}>
            <Text>{message}</Text>
        </View>
    );
}