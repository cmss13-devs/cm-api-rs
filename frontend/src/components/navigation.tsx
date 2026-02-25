import React, { useEffect, useRef, useState } from "react";
import { Link } from "react-router-dom";
import type { User } from "../types/global";
import { NameExpand } from "./nameExpand";

interface NavDropdownProps {
  label: string;
  children: React.ReactNode;
}

function NavDropdown({ label, children }: NavDropdownProps) {
  const [isOpen, setIsOpen] = useState(false);
  const dropdownRef = useRef<HTMLDivElement>(null);

  const closeDropdown = () => setIsOpen(false);

  useEffect(() => {
    function handleClickOutside(event: MouseEvent) {
      if (dropdownRef.current && !dropdownRef.current.contains(event.target as Node)) {
        setIsOpen(false);
      }
    }
    document.addEventListener("mousedown", handleClickOutside);
    return () => document.removeEventListener("mousedown", handleClickOutside);
  }, []);

  return (
    <div className="relative" ref={dropdownRef}>
      <button
        type="button"
        onClick={() => setIsOpen(!isOpen)}
        className="text-gray-300 hover:text-white hover:underline flex items-center gap-1"
      >
        {label}
        <svg
          className={`w-3 h-3 transition-transform ${isOpen ? "rotate-180" : ""}`}
          fill="none"
          stroke="currentColor"
          viewBox="0 0 24 24"
          aria-hidden="true"
        >
          <path strokeLinecap="round" strokeLinejoin="round" strokeWidth={2} d="M19 9l-7 7-7-7" />
        </svg>
      </button>
      {isOpen && (
        <div className="absolute top-full left-0 mt-1 py-1 min-w-[150px] foreground border border-gray-600 rounded shadow-lg z-50">
          {React.Children.map(children, (child) =>
            React.isValidElement<NavDropdownItemProps>(child)
              ? React.cloneElement(child, { onClick: closeDropdown })
              : child
          )}
        </div>
      )}
    </div>
  );
}

interface NavDropdownItemProps {
  to: string;
  children: React.ReactNode;
  onClick?: () => void;
}

function NavDropdownItem({ to, children, onClick }: NavDropdownItemProps) {
  const handleClick = () => {
    if (onClick) onClick();
  };

  return (
    <Link
      to={to}
      onClick={handleClick}
      className="block px-3 py-1.5 text-gray-300 hover:text-white hover:bg-gray-700/50"
    >
      {children}
    </Link>
  );
}

interface NavigationProps {
  user: User | undefined;
  onLogout: () => void;
}

export function Navigation({ user, onLogout }: NavigationProps) {
  const [mobileMenuOpen, setMobileMenuOpen] = useState(false);

  const closeMobileMenu = () => setMobileMenuOpen(false);

  return (
    <nav className="w-full foreground p-3">
      {/* Desktop Navigation */}
      <div className="hidden md:flex flex-row items-center gap-3">
        <Link to="/" className="text-white hover:underline font-bold">
          [cmdb]
        </Link>

        <span className="text-gray-500">|</span>

        {/* Bans Dropdown */}
        <NavDropdown label="Bans">
          <NavDropdownItem to="/bans">Active Bans</NavDropdownItem>
          <NavDropdownItem to="/ban-history">Ban History</NavDropdownItem>
          {user?.isStaff && (
            <NavDropdownItem to="/sticky">Stickybans</NavDropdownItem>
          )}
        </NavDropdown>

        {user?.isStaff && (
          <>
            <span className="text-gray-500">|</span>

            {/* Lookup Dropdown */}
            <NavDropdown label="Lookup">
              <NavDropdownItem to="/user">Player Lookup</NavDropdownItem>
              <NavDropdownItem to="/authentik">User Lookup</NavDropdownItem>
            </NavDropdown>

            <span className="text-gray-500">|</span>

            {/* Administrative Dropdown */}
            <NavDropdown label="Administrative">
              <NavDropdownItem to="/ticket">Tickets</NavDropdownItem>
              <NavDropdownItem to="/new_players">New Players</NavDropdownItem>
              <NavDropdownItem to="/whitelists">Whitelists</NavDropdownItem>
            </NavDropdown>
          </>
        )}

        {user?.manageable?.length ? (
          <>
            <span className="text-gray-500">|</span>
            <Link to="/user_manager" className="text-gray-300 hover:text-white hover:underline">
              User Manager
            </Link>
          </>
        ) : null}

        {/* User section - pushed to right */}
        {user && (
          <div className="ml-auto flex items-center gap-3">
            <span className="text-gray-400">
              {user.username} (
              {user.isStaff ? <NameExpand name={user.ckey} /> : user.ckey}
              )
            </span>
            <Link to="/account" className="text-gray-300 hover:text-white hover:underline">
              Account
            </Link>
            <button
              type="button"
              onClick={onLogout}
              className="text-red-400 hover:text-red-300 hover:underline"
            >
              Logout
            </button>
          </div>
        )}
      </div>

      {/* Mobile Navigation */}
      <div className="md:hidden flex items-center justify-between">
        <Link to="/" className="text-white hover:underline font-bold">
          [cmdb]
        </Link>

        <button
          type="button"
          onClick={() => setMobileMenuOpen(!mobileMenuOpen)}
          className="text-gray-400 hover:text-white p-1"
          aria-label="Toggle menu"
        >
          {mobileMenuOpen ? (
            <svg className="w-6 h-6" fill="none" stroke="currentColor" viewBox="0 0 24 24" aria-hidden="true">
              <path strokeLinecap="round" strokeLinejoin="round" strokeWidth={2} d="M6 18L18 6M6 6l12 12" />
            </svg>
          ) : (
            <svg className="w-6 h-6" fill="none" stroke="currentColor" viewBox="0 0 24 24" aria-hidden="true">
              <path strokeLinecap="round" strokeLinejoin="round" strokeWidth={2} d="M4 6h16M4 12h16M4 18h16" />
            </svg>
          )}
        </button>
      </div>

      {/* Mobile Menu */}
      {mobileMenuOpen && (
        <div className="md:hidden mt-3 pt-3 border-t border-gray-600 flex flex-col gap-2">
          {user && (
            <div className="text-gray-400 text-sm pb-2 border-b border-gray-700">
              {user.username} ({user.ckey})
            </div>
          )}

          <div className="text-gray-500 text-xs uppercase mt-2">Bans</div>
          <Link to="/bans" onClick={closeMobileMenu} className="text-gray-300 hover:text-white pl-2">
            Active Bans
          </Link>
          <Link to="/ban-history" onClick={closeMobileMenu} className="text-gray-300 hover:text-white pl-2">
            Ban History
          </Link>
          {user?.isStaff && (
            <Link to="/sticky" onClick={closeMobileMenu} className="text-gray-300 hover:text-white pl-2">
              Stickybans
            </Link>
          )}

          {user?.isStaff && (
            <>
              <div className="text-gray-500 text-xs uppercase mt-3">Lookup</div>
              <Link to="/user" onClick={closeMobileMenu} className="text-gray-300 hover:text-white pl-2">
                Player Lookup
              </Link>
              <Link to="/authentik" onClick={closeMobileMenu} className="text-gray-300 hover:text-white pl-2">
                User Lookup
              </Link>

              <div className="text-gray-500 text-xs uppercase mt-3">Administrative</div>
              <Link to="/ticket" onClick={closeMobileMenu} className="text-gray-300 hover:text-white pl-2">
                Tickets
              </Link>
              <Link to="/new_players" onClick={closeMobileMenu} className="text-gray-300 hover:text-white pl-2">
                New Players
              </Link>
              <Link to="/whitelists" onClick={closeMobileMenu} className="text-gray-300 hover:text-white pl-2">
                Whitelists
              </Link>
            </>
          )}

          {user?.manageable?.length ? (
            <>
              <div className="text-gray-500 text-xs uppercase mt-3">Management</div>
              <Link to="/user_manager" onClick={closeMobileMenu} className="text-gray-300 hover:text-white pl-2">
                User Manager
              </Link>
            </>
          ) : null}

          {user && (
            <>
              <div className="text-gray-500 text-xs uppercase mt-3">Account</div>
              <Link to="/account" onClick={closeMobileMenu} className="text-gray-300 hover:text-white pl-2">
                Settings
              </Link>
              <button
                type="button"
                onClick={() => {
                  closeMobileMenu();
                  onLogout();
                }}
                className="text-red-400 hover:text-red-300 text-left pl-2"
              >
                Logout
              </button>
            </>
          )}
        </div>
      )}
    </nav>
  );
}
