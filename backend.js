import React, { useState, useEffect, useRef } from "react";
import "./App.css";
import axios from "axios";

const BACKEND_URL = process.env.REACT_APP_BACKEND_URL;
const API = `${BACKEND_URL}/api`;

// Custom loading component with glittering MV
const MVLoadingScreen = () => {
  return (
    <div className="fixed inset-0 bg-gradient-to-br from-slate-900 to-purple-900 flex items-center justify-center z-50">
      <div className="text-center">
        <div className="text-8xl font-bold text-transparent bg-clip-text bg-gradient-to-r from-purple-400 via-pink-400 to-red-400 animate-pulse mb-4 glitter-text">
          MV
        </div>
        <div className="text-xl text-white/70">Loading Secure Messenger...</div>
      </div>
    </div>
  );
};

// Landing page component
const LandingPage = ({ onLogin, onRegister }) => {
  return (
    <div className="min-h-screen bg-gradient-to-br from-slate-900 via-purple-900 to-slate-900">
      {/* Header */}
      <header className="flex justify-between items-center p-6">
        <div className="text-2xl font-bold text-white">🔐</div>
        <div className="flex gap-4">
          <button
            onClick={onLogin}
            className="px-6 py-2 bg-purple-600 hover:bg-purple-700 text-white rounded-lg transition-colors duration-200 font-medium"
          >
            Login
          </button>
          <button
            onClick={onRegister}
            className="px-6 py-2 bg-transparent border-2 border-purple-400 hover:bg-purple-400 text-purple-400 hover:text-white rounded-lg transition-all duration-200 font-medium"
          >
            Register
          </button>
        </div>
      </header>

      {/* Main content */}
      <div className="flex flex-col items-center justify-center min-h-[80vh] text-center px-4">
        <div className="text-6xl md:text-8xl font-bold text-transparent bg-clip-text bg-gradient-to-r from-purple-400 via-pink-400 to-red-400 mb-8 glitter-text">
          SECURE MESSENGER
        </div>
        
        <p className="text-xl text-white/80 mb-12 max-w-2xl leading-relaxed">
          Experience military-grade encryption with AES-256 and steganography. 
          Your messages are hidden inside images and encrypted with unique keys.
        </p>

        <div className="grid md:grid-cols-3 gap-8 max-w-4xl">
          <div className="bg-white/10 backdrop-blur-lg rounded-xl p-6 border border-white/20">
            <div className="text-4xl mb-4">🔐</div>
            <h3 className="text-xl font-semibold text-white mb-2">AES-256 Encryption</h3>
            <p className="text-white/70">Military-grade encryption with unique keys for every message</p>
          </div>
          
          <div className="bg-white/10 backdrop-blur-lg rounded-xl p-6 border border-white/20">
            <div className="text-4xl mb-4">🖼️</div>
            <h3 className="text-xl font-semibold text-white mb-2">Steganography</h3>
            <p className="text-white/70">Messages hidden invisibly inside your chosen images</p>
          </div>
          
          <div className="bg-white/10 backdrop-blur-lg rounded-xl p-6 border border-white/20">
            <div className="text-4xl mb-4">🔔</div>
            <h3 className="text-xl font-semibold text-white mb-2">Secure Notifications</h3>
            <p className="text-white/70">Get notified instantly when you receive encrypted messages</p>
          </div>
        </div>

        <div className="mt-12 flex gap-4">
          <button
            onClick={onLogin}
            className="px-8 py-4 bg-gradient-to-r from-purple-600 to-pink-600 hover:from-purple-700 hover:to-pink-700 text-white rounded-xl font-semibold text-lg transition-all duration-200 transform hover:scale-105"
          >
            Get Started
          </button>
        </div>
      </div>
    </div>
  );
};

// Profile setup component
const ProfileSetup = ({ user, onComplete }) => {
  const [profilePicture, setProfilePicture] = useState("");
  const [isUploading, setIsUploading] = useState(false);
  const fileInputRef = useRef(null);

  const handleFileUpload = (event) => {
    const file = event.target.files[0];
    if (file && file.type.startsWith('image/')) {
      const reader = new FileReader();
      reader.onload = (e) => {
        setProfilePicture(e.target.result);
      };
      reader.readAsDataURL(file);
    }
  };

  const handleSubmit = async () => {
    if (!profilePicture) return;
    
    setIsUploading(true);
    try {
      await axios.post(`${API}/users/upload-profile-picture`, 
        new URLSearchParams({ profile_picture: profilePicture }),
        { withCredentials: true }
      );
      onComplete();
    } catch (error) {
      console.error('Failed to upload profile picture:', error);
    } finally {
      setIsUploading(false);
    }
  };

  return (
    <div className="min-h-screen bg-gradient-to-br from-slate-900 to-purple-900 flex items-center justify-center p-4">
      <div className="bg-white/10 backdrop-blur-lg rounded-2xl p-8 border border-white/20 max-w-md w-full">
        <h2 className="text-3xl font-bold text-white mb-6 text-center">Complete Your Profile</h2>
        
        <div className="text-center mb-6">
          <div className="w-32 h-32 mx-auto mb-4 rounded-full overflow-hidden bg-white/20">
            {profilePicture ? (
              <img src={profilePicture} alt="Profile" className="w-full h-full object-cover" />
            ) : (
              <div className="w-full h-full flex items-center justify-center text-white/50 text-4xl">
                👤
              </div>
            )}
          </div>
          
          <input
            type="file"
            ref={fileInputRef}
            onChange={handleFileUpload}
            accept="image/*"
            className="hidden"
          />
          
          <button
            onClick={() => fileInputRef.current?.click()}
            className="px-6 py-2 bg-purple-600 hover:bg-purple-700 text-white rounded-lg transition-colors duration-200"
          >
            Choose Profile Picture
          </button>
        </div>

        <div className="text-center text-white/70 mb-6">
          <p>Welcome, {user.name}!</p>
          <p className="text-sm">Please upload a profile picture to continue.</p>
        </div>

        <button
          onClick={handleSubmit}
          disabled={!profilePicture || isUploading}
          className="w-full px-6 py-3 bg-gradient-to-r from-purple-600 to-pink-600 hover:from-purple-700 hover:to-pink-700 disabled:from-gray-600 disabled:to-gray-600 text-white rounded-lg transition-all duration-200 font-medium disabled:cursor-not-allowed"
        >
          {isUploading ? "Uploading..." : "Complete Setup"}
        </button>
      </div>
    </div>
  );
};

// Main messenger component
const MessengerApp = ({ user, onLogout }) => {
  const [activeTab, setActiveTab] = useState("send");
  const [messages, setMessages] = useState([]);
  const [notifications, setNotifications] = useState([]);
  const [searchQuery, setSearchQuery] = useState("");
  const [searchResults, setSearchResults] = useState([]);
  const [selectedReceiver, setSelectedReceiver] = useState(null);
  const [messageContent, setMessageContent] = useState("");
  const [coverImage, setCoverImage] = useState("");
  const [isSending, setSending] = useState(false);
  const fileInputRef = useRef(null);
  const textareaRef = useRef(null);

  useEffect(() => {
    loadMessages();
    loadNotifications();
    const interval = setInterval(loadNotifications, 30000); // Check for new notifications every 30 seconds
    return () => clearInterval(interval);
  }, [activeTab]);

  const loadMessages = async () => {
    try {
      const endpoint = activeTab === "send" ? "/messages/sent" : "/messages/received";
      const response = await axios.get(`${API}${endpoint}`, { withCredentials: true });
      setMessages(response.data);
    } catch (error) {
      console.error('Failed to load messages:', error);
    }
  };

  const loadNotifications = async () => {
    try {
      const response = await axios.get(`${API}/notifications`, { withCredentials: true });
      setNotifications(response.data.filter(n => !n.is_read));
    } catch (error) {
      console.error('Failed to load notifications:', error);
    }
  };

  const searchUsers = async (query) => {
    if (!query.trim()) {
      setSearchResults([]);
      return;
    }
    
    try {
      const response = await axios.get(`${API}/users/search?query=${encodeURIComponent(query)}`, { withCredentials: true });
      setSearchResults(response.data);
    } catch (error) {
      console.error('Failed to search users:', error);
    }
  };

  const handleCoverImageUpload = (event) => {
    const file = event.target.files[0];
    if (file && file.type === 'image/png') {
      const reader = new FileReader();
      reader.onload = (e) => {
        // Convert to base64 without data URL prefix
        const base64 = e.target.result.split(',')[1];
        setCoverImage(base64);
      };
      reader.readAsDataURL(file);
    } else {
      alert('Please select a PNG image file');
    }
  };

  const handleKeyPress = (e) => {
    if (e.key === 'Enter' && !e.shiftKey) {
      e.preventDefault();
      sendMessage();
    }
  };

  const sendMessage = async () => {
    if (!selectedReceiver || !messageContent.trim() || !coverImage) {
      alert('Please select a receiver, enter a message, and upload a cover image');
      return;
    }

    setSending(true);
    try {
      await axios.post(`${API}/messages/send`, {
        receiver_id: selectedReceiver.id,
        content: messageContent,
        cover_image: coverImage
      }, { withCredentials: true });

      setMessageContent("");
      setCoverImage("");
      setSelectedReceiver(null);
      alert('Message sent successfully!');
      loadMessages();
    } catch (error) {
      console.error('Failed to send message:', error);
      alert('Failed to send message');
    } finally {
      setSending(false);
    }
  };

  const decryptMessage = async (messageId) => {
    try {
      const response = await axios.post(`${API}/messages/${messageId}/decrypt`, {}, { withCredentials: true });
      alert(`Decrypted message: ${response.data.decrypted_content}`);
      loadMessages();
    } catch (error) {
      console.error('Failed to decrypt message:', error);
      alert('Failed to decrypt message');
    }
  };

  const deleteMessage = async (messageId) => {
    if (window.confirm('Are you sure you want to delete this message?')) {
      try {
        await axios.delete(`${API}/messages/${messageId}`, { withCredentials: true });
        loadMessages();
      } catch (error) {
        console.error('Failed to delete message:', error);
      }
    }
  };

  return (
    <div className="min-h-screen bg-gradient-to-br from-slate-900 to-purple-900">
      {/* Header */}
      <header className="bg-black/20 backdrop-blur-lg border-b border-white/10 p-4">
        <div className="flex justify-between items-center">
          <div className="flex items-center gap-4">
            <h1 className="text-2xl font-bold text-white">🔐 Secure Messenger</h1>
            {notifications.length > 0 && (
              <div className="bg-red-500 text-white px-2 py-1 rounded-full text-sm">
                {notifications.length} new
              </div>
            )}
          </div>
          
          <div className="flex items-center gap-4">
            <div className="flex items-center gap-2 text-white">
              <img 
                src={user.profile_picture || user.picture} 
                alt={user.name}
                className="w-8 h-8 rounded-full"
              />
              <span>{user.name}</span>
            </div>
            <button
              onClick={onLogout}
              className="px-4 py-2 bg-red-600 hover:bg-red-700 text-white rounded-lg transition-colors duration-200"
            >
              Logout
            </button>
          </div>
        </div>
      </header>

      <div className="flex h-[calc(100vh-80px)]">
        {/* Sidebar */}
        <div className="w-80 bg-black/20 backdrop-blur-lg border-r border-white/10 p-4">
          <div className="flex gap-2 mb-6">
            <button
              onClick={() => setActiveTab("send")}
              className={`flex-1 py-2 px-4 rounded-lg transition-colors duration-200 ${
                activeTab === "send" 
                  ? "bg-purple-600 text-white" 
                  : "bg-white/10 text-white/70 hover:bg-white/20"
              }`}
            >
              Send Message
            </button>
            <button
              onClick={() => setActiveTab("received")}
              className={`flex-1 py-2 px-4 rounded-lg transition-colors duration-200 ${
                activeTab === "received" 
                  ? "bg-purple-600 text-white" 
                  : "bg-white/10 text-white/70 hover:bg-white/20"
              }`}
            >
              Received
            </button>
          </div>

          {activeTab === "send" && (
            <div className="space-y-4">
              <div>
                <label className="block text-white text-sm font-medium mb-2">Search Users</label>
                <input
                  type="text"
                  value={searchQuery}
                  onChange={(e) => {
                    setSearchQuery(e.target.value);
                    searchUsers(e.target.value);
                  }}
                  placeholder="Search by name or email..."
                  className="w-full px-3 py-2 bg-white/10 border border-white/20 rounded-lg text-white placeholder-white/50 focus:outline-none focus:ring-2 focus:ring-purple-500"
                />
                
                {searchResults.length > 0 && (
                  <div className="mt-2 bg-white/10 rounded-lg border border-white/20 max-h-40 overflow-y-auto">
                    {searchResults.map(user => (
                      <button
                        key={user.id}
                        onClick={() => {
                          setSelectedReceiver(user);
                          setSearchQuery("");
                          setSearchResults([]);
                        }}
                        className="w-full p-3 text-left hover:bg-white/10 transition-colors duration-200 flex items-center gap-3"
                      >
                        <img src={user.picture} alt={user.name} className="w-8 h-8 rounded-full" />
                        <div>
                          <div className="text-white font-medium">{user.name}</div>
                          <div className="text-white/60 text-sm">{user.email}</div>
                        </div>
                      </button>
                    ))}
                  </div>
                )}
              </div>

              {selectedReceiver && (
                <div className="bg-white/10 rounded-lg p-3 border border-white/20">
                  <div className="text-white text-sm">Sending to:</div>
                  <div className="flex items-center gap-2 mt-1">
                    <img src={selectedReceiver.picture} alt={selectedReceiver.name} className="w-6 h-6 rounded-full" />
                    <span className="text-white font-medium">{selectedReceiver.name}</span>
                  </div>
                </div>
              )}

              <div>
                <label className="block text-white text-sm font-medium mb-2">Cover Image (PNG)</label>
                <input
                  type="file"
                  ref={fileInputRef}
                  onChange={handleCoverImageUpload}
                  accept="image/png"
                  className="hidden"
                />
                <button
                  onClick={() => fileInputRef.current?.click()}
                  className="w-full px-4 py-2 bg-purple-600 hover:bg-purple-700 text-white rounded-lg transition-colors duration-200"
                >
                  {coverImage ? "Change Cover Image" : "Upload Cover Image"}
                </button>
                {coverImage && (
                  <div className="mt-2 text-green-400 text-sm">✓ Cover image uploaded</div>
                )}
              </div>

              <div>
                <label className="block text-white text-sm font-medium mb-2">Message</label>
                <textarea
                  ref={textareaRef}
                  value={messageContent}
                  onChange={(e) => setMessageContent(e.target.value)}
                  onKeyPress={handleKeyPress}
                  placeholder="Type your secure message... (Enter to send, Shift+Enter for new line)"
                  className="w-full px-3 py-2 bg-white/10 border border-white/20 rounded-lg text-white placeholder-white/50 focus:outline-none focus:ring-2 focus:ring-purple-500 h-32 resize-none"
                />
              </div>

              <button
                onClick={sendMessage}
                disabled={isSending || !selectedReceiver || !messageContent.trim() || !coverImage}
                className="w-full px-4 py-3 bg-gradient-to-r from-purple-600 to-pink-600 hover:from-purple-700 hover:to-pink-700 disabled:from-gray-600 disabled:to-gray-600 text-white rounded-lg transition-all duration-200 font-medium disabled:cursor-not-allowed"
              >
                {isSending ? "Encrypting & Sending..." : "Send Secure Message"}
              </button>
            </div>
          )}
        </div>

        {/* Main content */}
        <div className="flex-1 p-6 overflow-y-auto">
          <h2 className="text-2xl font-bold text-white mb-6">
            {activeTab === "send" ? "Send Secure Message" : "Received Messages"}
          </h2>

          {activeTab === "received" && (
            <div className="space-y-4">
              {messages.map(message => (
                <div key={message.id} className="bg-white/10 backdrop-blur-lg rounded-xl p-6 border border-white/20">
                  <div className="flex items-start justify-between mb-4">
                    <div className="flex items-center gap-3">
                      <img 
                        src={message.sender_picture} 
                        alt={message.sender_name}
                        className="w-10 h-10 rounded-full"
                      />
                      <div>
                        <div className="text-white font-medium">{message.sender_name}</div>
                        <div className="text-white/60 text-sm">
                          {new Date(message.created_at).toLocaleString()}
                        </div>
                      </div>
                    </div>
                    <div className="flex gap-2">
                      <button
                        onClick={() => decryptMessage(message.id)}
                        className="px-4 py-2 bg-green-600 hover:bg-green-700 text-white rounded-lg transition-colors duration-200 text-sm"
                      >
                        Decrypt
                      </button>
                      <button
                        onClick={() => deleteMessage(message.id)}
                        className="px-4 py-2 bg-red-600 hover:bg-red-700 text-white rounded-lg transition-colors duration-200 text-sm"
                      >
                        Delete
                      </button>
                    </div>
                  </div>
                  
                  <div className="bg-black/20 rounded-lg p-4">
                    <div className="text-white/60 text-sm mb-2">Steganography Image:</div>
                    <img 
                      src={`data:image/png;base64,${message.steganography_image}`}
                      alt="Hidden message"
                      className="max-w-full h-auto rounded-lg border border-white/20"
                    />
                    <div className="text-white/60 text-xs mt-2">
                      Click "Decrypt" to reveal the hidden message
                    </div>
                  </div>
                  
                  {!message.is_read && (
                    <div className="text-purple-400 text-sm mt-2">● Unread</div>
                  )}
                </div>
              ))}
              
              {messages.length === 0 && (
                <div className="text-center text-white/60 mt-12">
                  <div className="text-6xl mb-4">📭</div>
                  <p>No messages received yet</p>
                </div>
              )}
            </div>
          )}
        </div>
      </div>
    </div>
  );
};

// Main App component
function App() {
  const [loading, setLoading] = useState(true);
  const [user, setUser] = useState(null);
  const [requiresProfileSetup, setRequiresProfileSetup] = useState(false);

  useEffect(() => {
    checkAuth();
  }, []);

  useEffect(() => {
    // Handle session ID from URL fragment
    const handleSessionId = async () => {
      const fragment = window.location.hash.substring(1);
      const params = new URLSearchParams(fragment);
      const sessionId = params.get('session_id');
      
      if (sessionId) {
        setLoading(true);
        try {
          const response = await axios.post(`${API}/auth/process-session`, {
            session_id: sessionId
          }, { withCredentials: true });
          
          setUser(response.data.user);
          setRequiresProfileSetup(response.data.requires_profile_setup);
          
          // Clean URL
          window.history.replaceState({}, document.title, window.location.pathname);
        } catch (error) {
          console.error('Failed to process session:', error);
        } finally {
          setLoading(false);
        }
      }
    };

    handleSessionId();
  }, []);

  const checkAuth = async () => {
    try {
      const response = await axios.get(`${API}/auth/me`, { withCredentials: true });
      setUser(response.data.user);
      setRequiresProfileSetup(!response.data.user.profile_picture);
    } catch (error) {
      // Not authenticated
    } finally {
      setLoading(false);
    }
  };

  const handleLogin = () => {
    const redirectUrl = encodeURIComponent(`${window.location.origin}/`);
    window.location.href = `https://auth.emergentagent.com/?redirect=${redirectUrl}`;
  };

  const handleLogout = async () => {
    try {
      await axios.post(`${API}/auth/logout`, {}, { withCredentials: true });
      setUser(null);
      setRequiresProfileSetup(false);
    } catch (error) {
      console.error('Logout failed:', error);
    }
  };

  const handleProfileSetupComplete = () => {
    setRequiresProfileSetup(false);
    checkAuth(); // Refresh user data
  };

  if (loading) {
    return <MVLoadingScreen />;
  }

  if (!user) {
    return <LandingPage onLogin={handleLogin} onRegister={handleLogin} />;
  }

  if (requiresProfileSetup) {
    return <ProfileSetup user={user} onComplete={handleProfileSetupComplete} />;
  }

  return <MessengerApp user={user} onLogout={handleLogout} />;
}

export default App;